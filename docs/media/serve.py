"""Local server for rendering the animations in a browser.

Serves the repo at http://127.0.0.1:8796 and accepts the rendered files from capture.html
(POST /save/<name>.gif|.png), writing them into docs/img/. Local use only.

    python docs/media/serve.py
    open http://127.0.0.1:8796/docs/media/capture.html?src=tour.html&out=tour.gif
"""
from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
SAVE_DIR = ROOT / "docs" / "img"
MAX_BYTES = 50_000_000


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_POST(self):  # noqa: N802
        name = Path(unquote(self.path.removeprefix("/save/"))).name
        length = int(self.headers.get("Content-Length") or 0)
        if not self.path.startswith("/save/") or Path(name).suffix not in (".gif", ".png") or not 0 < length <= MAX_BYTES:
            self.send_error(400, "POST /save/<name>.gif or .png, up to 50 MB")
            return
        (SAVE_DIR / name).write_bytes(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"saved docs/img/{name}".encode())

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    print(f"serving {ROOT} on http://127.0.0.1:8796")
    ThreadingHTTPServer(("127.0.0.1", 8796), Handler).serve_forever()
