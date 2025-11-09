"""Flask application factory for the file displayer."""

from __future__ import annotations

import hashlib
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

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
TEXT_PREVIEW_LIMIT = 1024 * 1024  # 1 MB


@dataclass
class Entry:
    name: str
    rel_path: str
    is_dir: bool
    size: Optional[int]
    mimetype: Optional[str]


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
