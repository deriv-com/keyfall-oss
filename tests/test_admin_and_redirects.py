"""Admin revoke/restore, and the two copies of the redirect allowlist agreeing."""
from __future__ import annotations

import pytest

import admin
import allow_page
import mcp_server_auth as msa
from conftest import pkce


def test_connections_revoke_and_restore(world, monkeypatch):
    monkeypatch.setattr(admin, "PREFIX", "t:")
    monkeypatch.setattr(admin, "AUDIT_STREAM", "t:audit")
    _, tok = world.connect()
    rows = admin.list_connections(world.r)
    assert [(x["email"], x["role"], x["agent"]) for x in rows] == [("alice@example.com", "user", "Claude Code")]

    assert admin.revoke(world.r, "Alice@Example.com", by="admin@example.com") == 1
    assert world.call(tok["access_token"]).status_code == 401
    client_id = world.register().json()["client_id"]
    page = world.allow_page(world.authorize(client_id, pkce()[1]))
    assert page.status_code == 403

    assert admin.restore(world.r, "alice@example.com", by="admin@example.com") is True
    world.connect()
    events = [e["event"] for e in admin.recent_events(world.r, email="alice@example.com")]
    assert "revoked" in events and "restored" in events and "connect_blocked" in events


def test_cli_runs(world, monkeypatch, capsys):
    monkeypatch.setattr(admin, "PREFIX", "t:")
    monkeypatch.setattr(admin, "AUDIT_STREAM", "t:audit")
    monkeypatch.setattr(admin.redis_lib.Redis, "from_url", staticmethod(lambda *a, **k: world.r))
    world.connect()
    assert admin.main(["connections"]) == 0 and "1 connected agent" in capsys.readouterr().out
    assert admin.main(["events", "--limit", "5"]) == 0 and "connect_allowed" in capsys.readouterr().out


TABLE = [
    ("http://127.0.0.1:5555/callback", True),
    ("http://localhost:33418/callback", True),
    ("http://[::1]:8000/cb", True),
    ("https://agent.example.com/oauth/callback", True),
    ("cursor://anysphere.cursor-mcp/oauth/callback", True),
    ("http://evil.example.com/cb", False),
    ("https://agent.example.com/cb#x", False),
    ("vscode://some/cb", False),
    ("javascript:alert(1)", False),
    ("https:///nohost", False),
]


@pytest.mark.parametrize("uri,ok", TABLE)
def test_both_allowlist_copies_agree(uri, ok):
    assert msa.redirect_uri_allowed(uri) is ok
    assert allow_page.redirect_uri_allowed(uri) is ok


def test_blocked_domains_and_extra_app_callbacks(monkeypatch):
    monkeypatch.setenv("MCP_BLOCKED_REDIRECT_DOMAINS", "example.com")
    monkeypatch.setenv("MCP_EXTRA_REDIRECTS", "myagent://cb")
    for f in (msa.redirect_uri_allowed, allow_page.redirect_uri_allowed):
        assert f("https://agent.example.com/cb") is False
        assert f("myagent://cb") is True
