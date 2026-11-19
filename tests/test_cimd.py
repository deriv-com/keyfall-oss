"""Client ID Metadata Documents: the agent's client_id is an https URL its vendor hosts."""
from __future__ import annotations

import asyncio
import os

import pytest

import mcp_server_auth as msa
from conftest import pkce

AGENT = "https://agent.example.com/oauth/client.json"


def doc(**over):
    return {"client_id": AGENT, "client_name": "Example Agent", "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none", **over}


def test_full_sign_in_without_register_and_any_loopback_port(cimd_world):
    cimd_world.docs[AGENT] = doc()
    redirect = "http://127.0.0.1:49152/callback"   # the listener's port is not in the document
    client_id, tok = cimd_world.connect(redirect=redirect, client_id=AGENT)
    assert client_id == AGENT and cimd_world.call(tok["access_token"]).status_code == 200
    assert not cimd_world.r.keys("t:client:*")      # nothing was registered


def test_agents_may_ask_for_the_advertised_scope(cimd_world):
    """Claude Code's document lists no scope, then its /authorize asks for scope=mcp."""
    cimd_world.docs[AGENT] = doc(redirect_uris=["http://localhost/callback", "http://127.0.0.1/callback"])
    r = cimd_world.mcp.get("/authorize", params={
        "response_type": "code", "client_id": AGENT, "redirect_uri": "http://localhost:63138/callback",
        "code_challenge": pkce()[1], "code_challenge_method": "S256", "state": "s",
        "scope": msa.SCOPE, "resource": msa.RESOURCE_URL})
    assert r.status_code == 302, r.text
    assert r.headers["location"].startswith(os.environ["MCP_ALLOW_PAGE_URL"] + "?"), r.headers["location"]


def test_loopback_callback_is_never_shown_as_verified(cimd_world):
    """Any local app can reuse a vendor's client_id with its own listener: no badge at all."""
    cimd_world.docs[AGENT] = doc()
    page = cimd_world.allow_page(cimd_world.authorize(AGENT, pkce()[1], "http://127.0.0.1:5000/callback"))
    assert "Example Agent" in page.text
    assert 'class="badge' not in page.text


def test_https_callback_on_the_vendor_domain_is_verified(cimd_world, monkeypatch):
    monkeypatch.setenv("MCP_WEB_REDIRECT_DOMAINS", "agent.example.com,elsewhere.example.org")
    cimd_world.docs[AGENT] = doc(redirect_uris=["https://app.agent.example.com/oauth/callback",
                                                "https://elsewhere.example.org/cb"])
    page = cimd_world.allow_page(cimd_world.authorize(AGENT, pkce()[1], "https://app.agent.example.com/oauth/callback"))
    assert "Verified by agent.example.com" in page.text
    page = cimd_world.allow_page(cimd_world.authorize(AGENT, pkce()[1], "https://elsewhere.example.org/cb"))
    assert "Verified by" not in page.text


@pytest.mark.parametrize("bad", [
    doc(client_id="https://other.example.com/client.json"),     # document claims another id
    doc(redirect_uris=["http://evil.example.com/cb"]),          # return address not allowed
    doc(redirect_uris=[]),
    doc(token_endpoint_auth_method="client_secret_post"),       # a public document can't hold a secret
    "not a dict",
])
def test_bad_documents_are_refused(cimd_world, bad):
    cimd_world.docs[AGENT] = bad
    r = cimd_world.mcp.get("/authorize", params={
        "response_type": "code", "client_id": AGENT, "redirect_uri": "http://127.0.0.1:5000/callback",
        "code_challenge": pkce()[1], "code_challenge_method": "S256", "state": "s"})
    assert r.status_code == 400


def test_other_loopback_paths_and_hosts_still_must_match(cimd_world):
    cimd_world.docs[AGENT] = doc()
    for redirect in ("http://127.0.0.1:5000/other", "http://localhost:5000/callback"):
        r = cimd_world.mcp.get("/authorize", params={
            "response_type": "code", "client_id": AGENT, "redirect_uri": redirect,
            "code_challenge": pkce()[1], "code_challenge_method": "S256", "state": "s"})
        assert r.status_code == 400, redirect


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/client.json", "https://agent.example.com/", "https://agent.example.com/c.json?x=1",
    "https://user:pw@agent.example.com/c.json", "https://agent.example.com/../c.json",
    "https://agent.example.com./c.json",
    "https://agent.example.com/c.json\nforged log line",       # urlsplit drops the newline; we don't
    "https://agent.example.com/c\x1b[2J.json",                 # terminal escape
    "https://\u0430gent.example.com/c.json",                   # Cyrillic look-alike
    "https://agent.example.com:6379/c.json",                   # any port but 443
    "https://agent.example.com\\@evil.example.com/c.json",
])
def test_unsafe_client_id_urls_are_refused_before_any_fetch(url):
    assert msa._cimd_url_ok(url) is False


def test_trusted_hosts_limit_who_can_be_a_client(monkeypatch):
    monkeypatch.setenv("MCP_CIMD_TRUSTED_HOSTS", "agent.example.com")
    assert msa._cimd_url_ok(AGENT) and not msa._cimd_url_ok("https://elsewhere.example.com/c.json")


def test_hosts_resolving_to_private_addresses_are_refused():
    assert asyncio.run(msa._pinned_address("localhost", 443)) is None


def test_documents_are_cached(cimd_world):
    cimd_world.docs[AGENT] = doc()
    cimd_world.connect(redirect="http://127.0.0.1:5000/callback", client_id=AGENT)
    del cimd_world.docs[AGENT]                      # vendor offline: the cached copy still works
    cimd_world.connect(redirect="http://127.0.0.1:5000/callback", client_id=AGENT)


def test_default_port_spelled_out_is_fine():
    assert msa._cimd_url_ok("https://agent.example.com:443/oauth/client.json")


def test_redirect_uris_are_checked_as_stored_too():
    """Python reads http://evil.example.com\\@127.0.0.1/cb as loopback; a browser (and pydantic) as evil."""
    with pytest.raises(ValueError, match="not allowed"):
        msa.client_from_document(AGENT, doc(redirect_uris=["http://evil.example.com\\@127.0.0.1/cb"]))
