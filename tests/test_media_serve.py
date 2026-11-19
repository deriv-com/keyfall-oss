"""docs/media/serve.py answers only its own pages: no DNS rebinding, no cross-site writes, docs/ only."""
from __future__ import annotations

import http.client
import importlib.util
import os
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("media_serve", os.path.join(ROOT, "docs", "media", "serve.py"))
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(serve, "SAVE_DIR", tmp_path)
    httpd = serve.ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    def request(method, path, host=f"127.0.0.1:{port}", body=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Host": host, **({"Origin": origin} if origin else {})}
        conn.request(method, path, body=body, headers=headers)
        status = conn.getresponse().status
        conn.close()
        return status

    yield request, port, tmp_path
    httpd.shutdown()
    httpd.server_close()


def test_serves_docs_to_its_own_pages(server):
    request, port, _ = server
    assert request("GET", "/docs/media/README.md") == 200
    assert request("GET", "/docs/media/README.md", host=f"localhost:{port}") == 200


def test_dns_rebinding_and_files_outside_docs_are_refused(server):
    request, port, _ = server
    assert request("GET", "/docs/media/README.md", host=f"attacker.example:{port}") == 403
    assert request("GET", "/README.md") == 403
    assert request("GET", "/docs/../.git/config") != 200
    assert request("GET", "/docs/%2e%2e/.gitignore") != 200


def test_only_its_own_pages_may_save_images(server):
    request, port, saved = server
    assert request("POST", "/save/x.png", body=b"png", origin="https://attacker.example") == 403
    assert request("POST", "/save/x.png", body=b"png") == 403                     # no Origin at all
    assert not list(saved.iterdir())
    assert request("POST", "/save/x.png", body=b"png", origin=f"http://127.0.0.1:{port}") == 200
    assert (saved / "x.png").read_bytes() == b"png"
