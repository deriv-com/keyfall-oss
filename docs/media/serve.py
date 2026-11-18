"""Local server for rendering the animations in a browser.

Serves docs/ at http://127.0.0.1:8796/docs/ and accepts the rendered files from capture.html
(POST /save/<name>.gif|.png), writing them into docs/img/. Local use only.

    python docs/media/serve.py
    open http://127.0.0.1:8796/docs/media/capture.html?src=tour.html&out=tour.gif

Only requests addressed to this server itself are answered: a web page whose DNS name is pointed
at 127.0.0.1 (DNS rebinding) sends its own Host, and a page on another site that POSTs here sends
its own Origin, so neither can read files or overwrite the images.
"""
from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SAVE_DIR = DOCS / "img"
MAX_BYTES = 50_000_000


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DOCS), **kwargs)

    def _own_origins(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def _addressed_to_us(self) -> bool:
        return f"http://{self.headers.get('Host', '')}" in self._own_origins()

    def translate_path(self, path):
        # /docs/... maps into docs/ (the base class drops ".." parts, so nothing outside is reachable)
        return super().translate_path(path.removeprefix("/docs"))

    def do_GET(self):  # noqa: N802
        if not self._addressed_to_us() or not self.path.startswith("/docs/"):
            self.send_error(403)
            return
        super().do_GET()

    def do_HEAD(self):  # noqa: N802
        if not self._addressed_to_us() or not self.path.startswith("/docs/"):
            self.send_error(403)
            return
        super().do_HEAD()

    def do_POST(self):  # noqa: N802
        if not self._addressed_to_us() or self.headers.get("Origin") not in self._own_origins():
            self.send_error(403, "POST only from this server's own pages")
            return
        name = Path(unquote(self.path.removeprefix("/save/"))).name
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
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
    print(f"serving {DOCS} on http://127.0.0.1:8796/docs/")
    ThreadingHTTPServer(("127.0.0.1", 8796), Handler).serve_forever()
