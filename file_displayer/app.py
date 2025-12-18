"""Flask application factory for the file displayer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional
from urllib import error as urlerror
from urllib import request as urlrequest

from flask import (
    Flask,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)


BASE_DIRECTORY = Path("/etc/data").resolve()
DEFAULT_TEXT_PREVIEW_LIMIT = 20 * 1024 * 1024  # 20 MB
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _determine_preview_limit() -> int:
    raw_limit = os.getenv("TEXT_PREVIEW_LIMIT_BYTES")
    if raw_limit is None:
        return DEFAULT_TEXT_PREVIEW_LIMIT
    try:
        parsed = int(raw_limit)
    except ValueError:
        return DEFAULT_TEXT_PREVIEW_LIMIT
    # Keep a reasonable minimum to avoid degenerate values such as zero or negatives.
    return max(parsed, 1024)


TEXT_PREVIEW_LIMIT = _determine_preview_limit()
LOG_SOURCES: list[tuple[str, list[str]]] = [
    ("riesling-site", ["docker", "logs", "--tail", "50", "riesling-site"]),
    ("nginx-server", ["docker", "logs", "--tail", "20", "nginx-server"]),
]


@dataclass
class Entry:
    name: str
    rel_path: str
    is_dir: bool
    size: Optional[int]
    mimetype: Optional[str]


@dataclass
class LogReport:
    source: str
    command: str
    ips: List[str]
    error: Optional[str]


@dataclass
class GeoReport:
    ip: str
    location: Optional[str]
    coordinates: Optional[str]
    org: Optional[str]
    error: Optional[str]


class DirectoryTraversalError(Exception):
    """Raised when a path attempts to escape the base directory."""


def create_app() -> Flask:
    """Application factory."""

    app = Flask(__name__)
    code = (os.getenv("CODE") or "").strip()
    token = _generate_token(code) if code else None

    def is_protected() -> bool:
        return bool(token)

    def is_authorized() -> bool:
        if not is_protected():
            return True
        return request.cookies.get("file_displayer_token") == token

    def safe_target(raw_target: Optional[str]) -> Optional[str]:
        if not raw_target:
            return None
        cleaned = raw_target[:-1] if raw_target.endswith("?") else raw_target
        if cleaned.startswith("/"):
            return cleaned
        return None

    def enforce_authorization():
        if is_authorized():
            return None
        return redirect(url_for("login", next=request.full_path))

    def resolve_relative_path(rel_path: str | None) -> Path:
        candidate = (BASE_DIRECTORY / (rel_path or "")).resolve()
        if not _is_within_base(candidate):
            raise DirectoryTraversalError(rel_path or "")
        return candidate

    @app.before_request
    def ensure_directory_exists() -> None:
        if not BASE_DIRECTORY.exists():
            abort(404, description=f"Base directory {BASE_DIRECTORY} does not exist.")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not is_protected():
            return redirect(url_for("index"))

        error = None
        if request.method == "POST":
            target = safe_target(request.form.get("next") or request.args.get("next"))
        else:
            target = safe_target(request.args.get("next"))
        if request.method == "POST":
            submitted = request.form.get("code", "").strip()
            if _generate_token(submitted) == token:
                response = make_response(redirect(target or url_for("index")))
                response.set_cookie("file_displayer_token", token, httponly=True, samesite="Lax")
                return response
            error = "Incorrect passcode."

        return render_template("login.html", error=error, next_url=target)

    @app.route("/logout")
    def logout():
        response = make_response(redirect(url_for("login")))
        response.delete_cookie("file_displayer_token")
        return response

    @app.route("/")
    def index():
        if (auth_redirect := enforce_authorization()) is not None:
            return auth_redirect

        rel_path = request.args.get("path", "")
        try:
            current_dir = resolve_relative_path(rel_path)
        except DirectoryTraversalError:
            abort(404)

        if not current_dir.is_dir():
            abort(404)

        entries = _collect_entries(current_dir)
        breadcrumbs = _build_breadcrumbs(rel_path)
        parent_rel_path = _parent_path(rel_path)

        return render_template(
            "index.html",
            base_directory=str(BASE_DIRECTORY),
            breadcrumbs=breadcrumbs,
            entries=entries,
            parent_rel_path=parent_rel_path,
            protected=is_protected(),
        )

    @app.route("/admin")
    def admin():
        if (auth_redirect := enforce_authorization()) is not None:
            return auth_redirect

        log_reports = _collect_log_reports()
        geo_reports = _collect_geo_reports(log_reports)

        return render_template(
            "admin.html",
            log_reports=log_reports,
            geo_reports=geo_reports,
            protected=is_protected(),
        )

    @app.route("/view")
    def view_file():
        if (auth_redirect := enforce_authorization()) is not None:
            return auth_redirect

        rel_path = request.args.get("path")
        if not rel_path:
            abort(400)

        try:
            file_path = resolve_relative_path(rel_path)
        except DirectoryTraversalError:
            abort(404)

        if not file_path.is_file():
            abort(404)

        mimetype, _ = mimetypes.guess_type(str(file_path))
        if mimetype and mimetype.startswith("image/"):
            return render_template(
                "view.html",
                rel_path=rel_path,
                is_image=True,
                mimetype=mimetype,
                content=None,
                oversized=False,
            )

        if file_path.stat().st_size > TEXT_PREVIEW_LIMIT:
            content = None
            oversized = True
        else:
            oversized = False
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = file_path.read_text(encoding="utf-8", errors="replace")

        return render_template(
            "view.html",
            rel_path=rel_path,
            is_image=False,
            mimetype=mimetype,
            content=content,
            oversized=oversized,
        )

    @app.route("/raw")
    def raw_file():
        if (auth_redirect := enforce_authorization()) is not None:
            return auth_redirect

        rel_path = request.args.get("path")
        if not rel_path:
            abort(400)

        try:
            file_path = resolve_relative_path(rel_path)
        except DirectoryTraversalError:
            abort(404)

        if not file_path.exists():
            abort(404)

        return send_file(file_path)

    @app.errorhandler(404)
    def not_found(error):  # type: ignore[override]
        return render_template("error.html", message="The requested resource was not found."), 404

    @app.errorhandler(400)
    def bad_request(error):  # type: ignore[override]
        return render_template("error.html", message="Bad request."), 400

    @app.errorhandler(DirectoryTraversalError)
    def traversal_error(error):  # type: ignore[override]
        return render_template("error.html", message="Invalid file path."), 400

    return app


def _generate_token(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _is_within_base(candidate: Path) -> bool:
    try:
        candidate.relative_to(BASE_DIRECTORY)
    except ValueError:
        return False
    return True


def _collect_entries(directory: Path) -> List[Entry]:
    entries: List[Entry] = []
    for child in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        rel_path = str(child.relative_to(BASE_DIRECTORY))
        size = child.stat().st_size if child.is_file() else None
        mimetype, _ = mimetypes.guess_type(str(child))
        entries.append(
            Entry(
                name=child.name,
                rel_path=rel_path,
                is_dir=child.is_dir(),
                size=size,
                mimetype=mimetype,
            )
        )
    return entries


def _build_breadcrumbs(rel_path: str) -> List[dict[str, str]]:
    breadcrumbs: List[dict[str, str]] = []
    parts = [part for part in Path(rel_path).parts if part not in ("", ".")]
    accumulated: List[str] = []
    for part in parts:
        accumulated.append(part)
        breadcrumbs.append({"label": part, "path": "/".join(accumulated)})
    return breadcrumbs


def _parent_path(rel_path: str) -> Optional[str]:
    rel = Path(rel_path)
    if not rel.parts:
        return None
    parent = rel.parent
    return str(parent) if str(parent) != "." else ""


def _collect_log_reports() -> List[LogReport]:
    reports: List[LogReport] = []
    for source, command in LOG_SOURCES:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - defensive
            reports.append(
                LogReport(
                    source=source,
                    command=" ".join(command),
                    ips=[],
                    error=f"Command failed to run: {exc}",
                )
            )
            continue

        if completed.returncode != 0:
            message = completed.stderr.strip() or f"Command exited with status {completed.returncode}."
            reports.append(
                LogReport(source=source, command=" ".join(command), ips=[], error=message)
            )
            continue

        ips = _extract_ips(completed.stdout)
        reports.append(LogReport(source=source, command=" ".join(command), ips=ips, error=None))

    return reports


def _collect_geo_reports(log_reports: Iterable[LogReport]) -> List[GeoReport]:
    geo_reports: List[GeoReport] = []
    seen: set[str] = set()
    for report in log_reports:
        for ip in report.ips:
            if ip in seen:
                continue
            seen.add(ip)
            geo_reports.append(_geolocate_ip(ip))
    return geo_reports


def _extract_ips(log_output: str) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for match in IP_PATTERN.findall(log_output):
        try:
            ip_obj = ipaddress.ip_address(match)
        except ValueError:
            continue
        if not ip_obj.is_global:
            continue
        if match in seen:
            continue
        seen.add(match)
        ordered.append(match)
    return ordered


@lru_cache(maxsize=256)
def _geolocate_ip(ip: str) -> GeoReport:
    url = f"https://ipapi.co/{ip}/json/"
    try:
        with urlrequest.urlopen(url, timeout=3) as response:
            raw = response.read().decode("utf-8")
    except urlerror.URLError as exc:  # pragma: no cover - network failures
        reason = getattr(exc, "reason", None) or getattr(exc, "code", None) or exc
        return GeoReport(ip=ip, location=None, coordinates=None, org=None, error=str(reason))
    except Exception as exc:  # pragma: no cover - defensive
        return GeoReport(ip=ip, location=None, coordinates=None, org=None, error=str(exc))

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return GeoReport(ip=ip, location=None, coordinates=None, org=None, error="Malformed response from geolocation service.")

    if data.get("error"):
        return GeoReport(ip=ip, location=None, coordinates=None, org=None, error=data.get("reason") or "Lookup failed.")

    country = data.get("country_name") or data.get("country")
    region = data.get("region") or data.get("region_code") or data.get("state")
    city = data.get("city")
    location_parts = [part for part in (city, region, country) if part]
    location = ", ".join(location_parts) if location_parts else None

    latitude = data.get("latitude") or data.get("lat")
    longitude = data.get("longitude") or data.get("lon")
    coordinates = f"{latitude}, {longitude}" if latitude is not None and longitude is not None else None

    org = data.get("org") or data.get("organization") or data.get("asn")

    return GeoReport(ip=ip, location=location, coordinates=coordinates, org=org, error=None)
