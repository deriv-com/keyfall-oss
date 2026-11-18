"""End-to-end sign-in: discovery, register, Allow, code, tokens, tool calls."""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import jwt

import mcp_server_auth as msa
from conftest import INIT, MCP_HEADERS, REDIRECT, pkce


def tool_call(name, args=None, rid=2):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}


def call_tool(world, access_token, name, args=None):
    """initialize -> notifications/initialized -> tools/call on one MCP session; returns the tool's JSON."""
    init = world.call(access_token)
    assert init.status_code == 200, init.text
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {access_token}",
               "mcp-session-id": init.headers["mcp-session-id"]}
    world.mcp.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
    r = world.mcp.post("/mcp", json=tool_call(name, args), headers=headers)
    assert r.status_code == 200, r.text
    return json.loads(result_of(r)["content"][0]["text"])


def result_of(resp):
    """The JSON-RPC result from a JSON or SSE response."""
    text = resp.text
    if text.lstrip().startswith("{"):
        return json.loads(text)["result"]
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:])["result"]
    raise AssertionError(text)


def test_metadata_points_agents_at_this_server_and_offers_cimd(world):
    pr = world.mcp.get("/.well-known/oauth-protected-resource/mcp").json()
    assert pr["resource"] == msa.RESOURCE_URL
    assert [s.rstrip("/") for s in pr["authorization_servers"]] == ["https://mcp.example.com"]
    asm = world.mcp.get("/.well-known/oauth-authorization-server").json()
    assert asm["authorization_endpoint"] == "https://mcp.example.com/authorize"
    assert asm["registration_endpoint"] == "https://mcp.example.com/register"
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["client_id_metadata_document_supported"] is True
    assert asm["authorization_response_iss_parameter_supported"] is True


def test_mcp_without_token_is_401_with_sign_in_hint(world):
    r = world.mcp.post("/mcp", json=INIT, headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]


def test_register_refuses_disallowed_return_addresses(world):
    for uri in ("http://evil.example.com/cb", "https://x.example.com/cb#frag", "vscode://x/cb"):
        r = world.register(uri)
        assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri", uri
    assert world.register("cursor://anysphere.cursor-mcp/oauth/callback", "Cursor").status_code == 201


def test_full_sign_in_then_tools(world):
    _, tok = world.connect()
    assert tok["token_type"].lower() == "bearer" and tok["expires_in"] == 3600 and tok["refresh_token"]
    assert world.call(tok["access_token"]).status_code == 200
    who = call_tool(world, tok["access_token"], "whoami")
    assert who == {"email": "alice@example.com", "name": "Alice Example", "role": "user"}
    events = [f["event"] for _, f in world.r.xrange("t:audit")]
    assert events[:2] == ["connect_allowed", "connected"] and "tool_call" in events


def test_readonly_role_sees_trimmed_record(world, monkeypatch):
    monkeypatch.setenv("FAKE_LOGIN_GROUPS", "mcp-readonly")
    _, tok = world.connect()
    rec = call_tool(world, tok["access_token"], "get_record", {"record_id": "R-100"})
    assert rec["title"] and "body" not in rec and rec["body_hidden"]


def test_code_works_once(world):
    client_id, verifier, code = world.sign_in()
    assert world.token(client_id, verifier, code).status_code == 200
    r = world.token(client_id, verifier, code)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_wrong_pkce_secret_is_refused(world):
    client_id, _, code = world.sign_in()
    r = world.token(client_id, pkce()[0], code)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_code_for_another_agent_is_refused(world):
    _, verifier, code = world.sign_in()
    other = world.register().json()["client_id"]
    assert world.token(other, verifier, code).json()["error"] == "invalid_grant"


def test_forged_or_wrong_audience_code_is_refused(world):
    client_id = world.register().json()["client_id"]
    claims = {"iss": msa.CODE_ISSUER, "aud": msa.CODE_AUDIENCE, "iat": 1, "exp": 9999999999, "jti": "x",
              "sub": "a@example.com", "role": "admin", "client_id": client_id, "redirect_uri": REDIRECT,
              "code_challenge": pkce()[1]}
    forged = jwt.encode(claims, "x" * 64, algorithm="HS256")
    assert world.token(client_id, "v", forged).json()["error"] == "invalid_grant"
    note_as_code = jwt.encode({**claims, "aud": msa.REQUEST_AUDIENCE}, "k" * 64, algorithm="HS256")
    assert world.token(client_id, "v", note_as_code).json()["error"] == "invalid_grant"


def test_redis_holds_only_token_hashes(world):
    _, tok = world.connect()
    dump = " ".join(world.r.keys("*")) + " ".join(
        json.dumps(world.r.hgetall(k)) if world.r.type(k) == "hash" else str(world.r.get(k) or "")
        for k in world.r.keys("*") if world.r.type(k) in ("hash", "string"))
    assert tok["access_token"] not in dump and tok["refresh_token"] not in dump


def test_authorize_errors_never_bounce_to_a_website(world):
    """Anyone can register an https callback, so /authorize errors must not redirect there
    (an open redirect on the public host, RFC 9700 4.11.2). Agents on this computer still get theirs."""
    evil = "https://phish.example.net/login"
    cid = world.register(evil).json()["client_id"]
    good = {"response_type": "code", "client_id": cid, "redirect_uri": evil, "code_challenge": pkce()[1], "state": "s"}
    for params in ({"client_id": cid, "redirect_uri": evil},                       # response_type missing
                   {**good, "scope": "bogus"},
                   {**good, "resource": "https://elsewhere.example/mcp"}):
        r = world.mcp.get("/authorize", params=params)
        assert r.status_code == 400 and "location" not in r.headers, params
        assert r.json()["error"]
    local = world.register().json()["client_id"]
    r = world.mcp.get("/authorize", params={**good, "client_id": local, "redirect_uri": REDIRECT, "scope": "bogus"})
    assert r.status_code == 302 and r.headers["location"].startswith(REDIRECT + "?error=invalid_scope")


def test_authorize_refuses_a_challenge_that_is_not_s256(world):
    cid = world.register().json()["client_id"]
    for challenge in ("short", "x" * 6000, pkce()[1] + "="):
        r = world.mcp.get("/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
                                                "code_challenge": challenge, "state": "s"})
        assert r.status_code == 302 and "error=invalid_request" in r.headers["location"], challenge


def test_registration_size_is_capped(world):
    """/register is open to anyone; one call must not park megabytes in Redis for 90 days."""
    assert world.register(name="N" * 200_000).status_code == 400
    r = world.mcp.post("/register", json={"redirect_uris": [f"http://127.0.0.1:{p}/cb" for p in range(1, 12)],
                                          "token_endpoint_auth_method": "none"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
    assert not world.r.keys("t:client:*")
    assert world.register().status_code == 201


def test_used_code_is_remembered_until_after_it_expires(world):
    """If the Allow page's clock runs ahead, its code's exp is later: the replay guard must outlast it."""
    client_id, verifier, code = world.sign_in()
    claims = jwt.decode(code, options={"verify_signature": False})
    ahead = jwt.encode({**claims, "exp": claims["exp"] + 3600}, "k" * 64, algorithm="HS256")
    assert world.token(client_id, verifier, ahead).status_code == 200
    assert world.r.ttl(f"t:code-used:{claims['jti']}") > 3600


def test_every_authorization_response_names_its_issuer(world):
    """RFC 9207 (a SHOULD in the MCP spec): iss on the code, on Cancel and on /authorize errors,
    equal to the metadata's issuer, so an agent using several servers can't be mixed up."""
    issuer = world.mcp.get("/.well-known/oauth-authorization-server").json()["issuer"]

    def iss(location):
        return parse_qs(urlsplit(location).query).get("iss")

    cid = world.register().json()["client_id"]
    for decision in ("allow", "deny"):
        r = world.decide(world.authorize(cid, pkce()[1]), decision=decision)
        assert iss(r.headers["location"]) == [issuer], decision
    r = world.mcp.get("/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
                                            "code_challenge": pkce()[1], "scope": "bogus"})
    assert r.status_code == 302 and iss(r.headers["location"]) == [issuer]
