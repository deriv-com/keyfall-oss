"""Walk the whole sign-in against the running demo, the way an agent does, and call a tool.

    python demo/smoke_test.py            (after demo/README.md step 1)

Prints each step. Uses only httpx; no agent needed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sys
from urllib.parse import parse_qs, urlsplit

import httpx

MCP = "http://localhost:8000"
REDIRECT = "http://127.0.0.1:53682/callback"   # an agent's local listener (nothing needs to run there)
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def step(n, text):
    print(f"{n:>2}. {text}")


def rpc(http, token, body, session=None):
    headers = {**ACCEPT, "Authorization": f"Bearer {token}", **({"mcp-session-id": session} if session else {})}
    r = http.post(f"{MCP}/mcp", json=body, headers=headers)
    data = r.text
    for line in data.splitlines():
        if line.startswith("data:"):
            data = line[5:]
    return r, (json.loads(data) if data.strip().startswith("{") else None)


def main() -> int:
    http = httpx.Client(follow_redirects=False, timeout=10)
    r = http.post(f"{MCP}/mcp", json={}, headers=ACCEPT)
    step(1, f"POST /mcp without a token -> {r.status_code}, {r.headers.get('www-authenticate', '')[:70]}...")
    asm = http.get(f"{MCP}/.well-known/oauth-authorization-server").json()
    step(2, f"discovery: authorize={asm['authorization_endpoint']}, CIMD={asm.get('client_id_metadata_document_supported')}")
    client_id = http.post(f"{MCP}/register", json={
        "client_name": "Smoke Test Agent", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]}).json()["client_id"]
    step(3, f"POST /register -> client_id {client_id[:12]}...")

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = http.get(f"{MCP}/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "s1",
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": f"{MCP}/mcp"})
    allow_url = r.headers["location"]
    step(4, f"secret kept, hash sent; /authorize -> {r.status_code} to {allow_url.split('?')[0]}")

    page = http.get(allow_url)
    title = re.search(r"<h1>(.*?)</h1>", page.text)
    step(5, f"Allow page -> {page.status_code}: {title.group(1) if title else page.text[:80]}")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page.text).group(1)
    req = parse_qs(urlsplit(allow_url).query)["req"][0]
    r = http.post(allow_url.split("?")[0], data={"req": req, "csrf": csrf, "decision": "allow"})
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    step(6, f"clicked Allow -> {r.status_code}, 60-second code delivered to {REDIRECT}")

    tok = http.post(f"{MCP}/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                         "redirect_uri": REDIRECT, "code_verifier": verifier}).json()
    step(7, f"POST /token with code + secret -> access token ({tok['expires_in']} s) + refresh token")

    r, _ = rpc(http, tok["access_token"], {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}}})
    session = r.headers["mcp-session-id"]
    rpc(http, tok["access_token"], {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, out = rpc(http, tok["access_token"], {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                             "params": {"name": "whoami", "arguments": {}}}, session)
    step(8, f"tool whoami -> {out['result']['content'][0]['text']}")

    again = http.post(f"{MCP}/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                           "redirect_uri": REDIRECT, "code_verifier": verifier})
    step(9, f"same code again -> {again.status_code} {again.json().get('error')} (works once)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
