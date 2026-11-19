"""Shared test setup: both hosts in-process, sharing one in-memory Redis.

The MCP server runs at https://mcp.example.com and the Allow page at http://localhost:8001 with
the demo-only fake login, so a whole sign-in runs without any network or SSO.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sys
from urllib.parse import parse_qs, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "reference"), os.path.join(ROOT, "demo")]

KEY = "k" * 64
os.environ.update({
    "MCP_SIGNING_KEY": KEY,
    "MCP_ISSUER_URL": "https://mcp.example.com",
    "MCP_ALLOW_PAGE_URL": "http://localhost:8001/connect-agent/authorize",
    "MCP_REDIS_PREFIX": "t:",
    "LOGIN_CHECK": "fake",
    "DEMO_ONLY": "1",
    "FAKE_LOGIN_EMAIL": "alice@example.com",
    "FAKE_LOGIN_GROUPS": "mcp-user",
})

import fakeredis  # noqa: E402
import pytest  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import allow_page  # noqa: E402
import mcp_server_auth as msa  # noqa: E402
from allow_app import app as allow_asgi  # noqa: E402
from demo_server import create_app  # noqa: E402

REDIRECT = "http://127.0.0.1:5555/callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}


class World:
    """Both apps plus the shared Redis (sync view for assertions and the Allow page)."""

    def __init__(self, mcp: TestClient, allow: TestClient, redis_sync, redis_async):
        self.mcp, self.allow, self.r, self.ar = mcp, allow, redis_sync, redis_async

    # agent side -------------------------------------------------------------------------
    def register(self, redirect=REDIRECT, name="Claude Code"):
        return self.mcp.post("/register", json={
            "redirect_uris": [redirect], "client_name": name, "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        })

    def authorize(self, client_id, challenge, redirect=REDIRECT, state="st-1"):
        r = self.mcp.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "resource": msa.RESOURCE_URL,
        })
        assert r.status_code == 302, r.text
        loc = urlsplit(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == os.environ["MCP_ALLOW_PAGE_URL"]
        return parse_qs(loc.query)["req"][0]

    # person side ------------------------------------------------------------------------
    def allow_page(self, req):
        return self.allow.get("/connect-agent/authorize", params={"req": req})

    def decide(self, req, decision="allow", csrf=None):
        if csrf is None:
            page = self.allow_page(req)
            assert page.status_code == 200, page.text
            csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page.text).group(1)
        return self.allow.post("/connect-agent/authorize", data={"req": req, "csrf": csrf, "decision": decision})

    def sign_in(self, redirect=REDIRECT, client_id=None):
        """Full sign-in up to the code. Returns (client_id, verifier, code)."""
        client_id = client_id or self.register(redirect).json()["client_id"]
        verifier, challenge = pkce()
        req = self.authorize(client_id, challenge, redirect)
        r = self.decide(req)
        assert r.status_code == 303, r.text
        q = parse_qs(urlsplit(r.headers["location"]).query)
        assert q["state"] == ["st-1"]
        return client_id, verifier, q["code"][0]

    def token(self, client_id, verifier, code, redirect=REDIRECT):
        return self.mcp.post("/token", data={"grant_type": "authorization_code", "code": code,
                                             "redirect_uri": redirect, "client_id": client_id,
                                             "code_verifier": verifier})

    def refresh(self, client_id, refresh_token):
        return self.mcp.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token,
                                             "client_id": client_id})

    def connect(self, **kw):
        client_id, verifier, code = self.sign_in(**kw)
        r = self.token(client_id, verifier, code, kw.get("redirect", REDIRECT))
        assert r.status_code == 200, r.text
        return client_id, r.json()

    def call(self, access_token, body=INIT):
        return self.mcp.post("/mcp", json=body, headers={**MCP_HEADERS, "Authorization": f"Bearer {access_token}"})


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


@pytest.fixture
def world(monkeypatch):
    server = fakeredis.FakeServer()
    r_sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    r_async = fakeredis.FakeAsyncRedis(server=server, decode_responses=True)
    monkeypatch.setattr(allow_page, "_redis", r_sync)
    app = create_app(r_async)
    with TestClient(app, base_url="https://mcp.example.com", follow_redirects=False) as mcp, \
            TestClient(allow_asgi, base_url="http://localhost:8001", follow_redirects=False) as allow:
        yield World(mcp, allow, r_sync, r_async)


@pytest.fixture
def cimd_world(monkeypatch):
    """Like world, but metadata documents come from a dict instead of the network."""
    docs = {}

    async def fetch(url):
        if url not in docs:
            raise ValueError("not found")
        return docs[url], 3600

    server = fakeredis.FakeServer()
    r_sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    r_async = fakeredis.FakeAsyncRedis(server=server, decode_responses=True)
    monkeypatch.setattr(allow_page, "_redis", r_sync)
    app = create_app(r_async, fetch_document=fetch)
    with TestClient(app, base_url="https://mcp.example.com", follow_redirects=False) as mcp, \
            TestClient(allow_asgi, base_url="http://localhost:8001", follow_redirects=False) as allow:
        w = World(mcp, allow, r_sync, r_async)
        w.docs = docs
        yield w
