"""The Allow page refuses whenever anything is uncertain, and is safe to show."""
from __future__ import annotations

import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest

import allow_page
from conftest import KEY, REDIRECT, pkce


def note(world, redirect=REDIRECT, name="Claude Code"):
    client_id = world.register(redirect, name).json()["client_id"]
    return world.authorize(client_id, pkce()[1], redirect)


def test_page_shows_who_what_and_where(world):
    page = world.allow_page(note(world))
    assert page.status_code == 200
    for text in ("Allow Claude Code to use My App as you?", "alice@example.com", "an app on this computer",
                 "Name given by the agent itself"):
        assert text in page.text
    h = page.headers
    assert "frame-ancestors 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store"
    assert "form-action 'self' http://127.0.0.1:5555" in h["content-security-policy"]


def test_agent_name_is_escaped(world):
    page = world.allow_page(note(world, name="<script>alert(1)</script>"))
    assert "<script>alert(1)" not in page.text and "&lt;script&gt;" in page.text


def test_cancel_returns_access_denied(world):
    r = world.decide(note(world), decision="deny")
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert r.status_code == 303 and q["error"] == ["access_denied"] and q["state"] == ["st-1"]


def test_code_lives_60_seconds_and_carries_the_redirect(world):
    r = world.decide(note(world))
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    claims = jwt.decode(code, KEY, algorithms=["HS256"], audience=allow_page.CODE_AUDIENCE)
    assert claims["exp"] - claims["iat"] == 60 and claims["redirect_uri"] == REDIRECT
    assert claims["redirect_uri_provided_explicitly"] is True and claims["role"] == "user"


def test_no_key_means_503(world, monkeypatch):
    req = note(world)
    monkeypatch.setenv("MCP_SIGNING_KEY", "short")
    assert world.allow_page(req).status_code == 503


@pytest.mark.parametrize("groups", ["", "some-other-group"])
def test_person_without_an_allowed_group_gets_403_on_get_and_post(world, monkeypatch, groups):
    req = note(world)
    monkeypatch.setenv("FAKE_LOGIN_GROUPS", groups)
    assert world.allow_page(req).status_code == 403
    assert world.decide(req, csrf="x").status_code == 403


def test_default_role_for_setups_without_groups(world, monkeypatch):
    monkeypatch.setenv("FAKE_LOGIN_GROUPS", "")
    monkeypatch.setenv("MCP_DEFAULT_ROLE", "readonly")
    page = world.allow_page(note(world))
    assert page.status_code == 200 and "full record bodies stay hidden" in page.text


def test_highest_role_wins(world, monkeypatch):
    monkeypatch.setenv("FAKE_LOGIN_GROUPS", "mcp-readonly,MCP-Admin")
    assert ">admin<" in world.allow_page(note(world)).text


def test_fake_login_only_works_on_localhost(world, monkeypatch):
    req = note(world)
    assert world.allow.get("http://approve.example.com/connect-agent/authorize", params={"req": req}).status_code == 403
    monkeypatch.setenv("DEMO_ONLY", "0")
    assert world.allow_page(req).status_code == 403


def test_bad_expired_and_wrong_key_notes_are_refused(world):
    now = int(time.time())
    base = {"iss": allow_page.REQUEST_ISSUER, "aud": allow_page.REQUEST_AUDIENCE, "iat": now, "exp": now + 600,
            "client_id": "c", "redirect_uri": REDIRECT, "code_challenge": "x" * 43, "code_challenge_method": "S256"}
    cases = [
        "garbage",
        jwt.encode({**base, "exp": now - 1}, KEY, algorithm="HS256"),
        jwt.encode(base, "w" * 64, algorithm="HS256"),
        jwt.encode({**base, "code_challenge_method": "plain"}, KEY, algorithm="HS256"),
        jwt.encode({**base, "redirect_uri": "http://evil.example.com/cb"}, KEY, algorithm="HS256"),
        jwt.encode({**base, "iat": now - 700, "exp": now + 600}, KEY, algorithm="HS256"),
        jwt.encode({**base, "aud": allow_page.CODE_AUDIENCE}, KEY, algorithm="HS256"),
    ]
    for req in cases:
        assert world.allow_page(req).status_code == 400, req


def test_csrf_from_another_note_is_refused(world):
    a, b = note(world), note(world)
    other_csrf = allow_page.csrf_token("alice@example.com", a, KEY.encode())
    assert world.decide(b, csrf=other_csrf).status_code == 400


def test_revoked_person_gets_no_button_and_revoke_check_fails_closed(world, monkeypatch):
    req = note(world)
    world.r.set("t:revoked:alice@example.com", "{}")
    page = world.allow_page(req)
    assert page.status_code == 403 and "Allow</button>" not in page.text
    world.r.delete("t:revoked:alice@example.com")

    class Down:
        def exists(self, *_):
            raise ConnectionError("redis down")

        def xadd(self, *_, **__):
            raise ConnectionError("redis down")

    monkeypatch.setattr(allow_page, "_redis", Down())
    page = world.allow_page(req)
    assert page.status_code == 503 and "Allow</button>" not in page.text


def test_web_callback_gets_a_navigation_hand_off(world):
    redirect = "https://agent.example.com/oauth/callback"
    r = world.decide(note(world, redirect))
    assert r.status_code == 200 and 'http-equiv="refresh"' in r.text
    assert "https://www.agent.example.com" in r.headers["content-security-policy"] or "agent.example.com" in r.text


def test_existing_query_on_redirect_is_kept(world):
    redirect = "http://127.0.0.1:5555/callback?session=abc"
    r = world.decide(note(world, redirect))
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["session"] == ["abc"] and "code" in q
