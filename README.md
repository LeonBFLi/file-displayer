# File Displayer

A lightweight Flask web application for browsing and viewing the files located in `/etc/data` inside the container. The app can be bundled into a small container image and exposes a passcode-protected interface on port `8888`.

## Features

- Browse the `/etc/data` directory with breadcrumb navigation.
- View text files directly in the browser (up to 1&nbsp;MB) and download larger files.
- Preview common image formats inline.
- Optional passcode protection controlled via the `CODE` environment variable.

## Requirements

- Python 3.11+
- Pip

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application locally:

```bash
export CODE=your-secret-code   # optional
python -m file_displayer
```

Then visit [http://localhost:8888](http://localhost:8888).

## Container image

Build the container image:

```bash
docker build -t file-displayer:latest .
```

Run the container, forwarding port 8888 and providing a passcode:

```bash
docker run \
  -p 8888:8888 \
  -e CODE=11995331 \
  file-displayer:latest
```

Visit [http://localhost:8888](http://localhost:8888) and enter the passcode when prompted.

> **Note:** Mount `/etc/data` with your own files if desired, e.g. `-v /path/on/host:/etc/data:ro`.

## Environment variables

| Variable | Description |
|----------|-------------|
| `CODE`   | Passcode required to access the UI. Leave unset or empty to disable authentication. |

## Development notes

- The application only serves files that reside within `/etc/data`. Attempts to traverse outside are blocked.
- Text file previews are limited to 1&nbsp;MB to keep rendering responsive; larger files can still be downloaded.
