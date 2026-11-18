"""Admin revoke/restore, and the two copies of the redirect allowlist agreeing."""
from __future__ import annotations

import inspect

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
    ("HTTP://LOCALHOST:5555/cb", True),
    ("http://[::ffff:7f00:1]:5555/cb", True),
    ("http://localhost.evil.example.com/cb", False),
    ("http://evil.example.com\\@127.0.0.1/cb", False),   # Python: 127.0.0.1; browsers: evil.example.com
    ("http://user:pw@127.0.0.1:5555/cb", False),
    ("http://@127.0.0.1:5555/cb", False),
    ("https://agent.example.com/cb#", False),             # an empty fragment is still a fragment
    ("http://127.0.0.1:5555/c b", False),
    ("http://127.0.0.1:5555/cb\n", False),
    ("https://ex\u00e4mple.com/cb", False),                # raw IDN: only the xn-- form is accepted
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
        assert f("https://agent.example.com./cb") is False      # trailing dot: same host, still blocked
        assert f("https://EXAMPLE.COM./cb") is False
        assert f("https://agent%2Eexample.com/cb") is False     # browsers decode %2E: same host, still blocked
        assert f("https://%65xample.com/cb") is False
        assert f("myagent://cb") is True


SHARED = ("_env_set", "app_redirects", "_is_loopback", "redirect_uri_allowed", "display_name")


@pytest.mark.parametrize("name", SHARED)
def test_the_two_copies_are_identical(name):
    """allow_page.py and mcp_server_auth.py run on different hosts, so the shared checks are copies."""
    assert inspect.getsource(getattr(msa, name)) == inspect.getsource(getattr(allow_page, name))


def test_the_two_copies_share_their_constants():
    for name in ("LOOPBACK_HOSTS", "DEFAULT_APP_REDIRECTS", "REQUEST_ISSUER", "REQUEST_AUDIENCE", "CODE_ISSUER",
                 "CODE_AUDIENCE", "MIN_KEY_BYTES"):
        assert getattr(msa, name) == getattr(allow_page, name), name
    assert msa.PKCE_CHALLENGE.pattern == allow_page.PKCE_CHALLENGE.pattern


def test_cli_prints_escapes_not_terminal_controls(world, monkeypatch, capsys):
    """Audit fields can carry anything (older events, other writers): escapes must not reach the terminal."""
    monkeypatch.setattr(admin, "AUDIT_STREAM", "t:audit")
    monkeypatch.setattr(admin.redis_lib.Redis, "from_url", staticmethod(lambda *a, **k: world.r))
    world.r.xadd("t:audit", {"event": "tool_call", "email": "a@example.com", "ts": "1",
                             "args": "\x1b[1A\x1b[2Khidden", "client_name": "x‮y"})
    assert admin.main(["events"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "‮" not in out and "\\x1b[1A" in out and "\\u202e" in out
