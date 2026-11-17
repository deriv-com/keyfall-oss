# When it breaks

## Quick checks against a deployed server

```bash
# 401 from YOUR server (not an SSO login page), with the metadata pointer
curl -si -X POST https://<mcp-host>/mcp -H 'Content-Type: application/json' -d '{}' | grep -iE '^HTTP|www-authenticate'

curl -s https://<mcp-host>/.well-known/oauth-protected-resource/mcp
curl -s https://<mcp-host>/.well-known/oauth-authorization-server     # S256 only, CIMD true

# The Allow page without an SSO session must NOT be reachable (expect the SSO redirect)
curl -si https://<approval-host>/connect-agent/authorize | head -1
```

## Symptoms

| Symptom | Likely cause | Fix |
|---|---|---|
| The agent shows an HTML page or "invalid JSON" when connecting | The MCP host is behind the SSO proxy | Take the proxy off `<mcp-host>`, or add a bypass rule for it |
| `/mcp` answers `421 Invalid Host header` | DNS-rebinding protection is on behind a proxy | `TransportSecuritySettings(enable_dns_rebinding_protection=False)` (already set in `build_mcp`) |
| `/mcp` answers 500 on every call | The MCP session manager is not running: the app is mounted but its lifespan never started | Enter `mcp_app.router.lifespan_context(mcp_app)` in your app's lifespan (see the end of `mcp_server_auth.py`) |
| Calls fail at random with `404 Session not found` | More than one worker process | One worker per replica; sticky sessions across replicas |
| Streaming hangs, or arrives all at once | Proxy buffering | `proxy_buffering off`, `proxy_http_version 1.1`, `proxy_read_timeout 300s` |
| `/register` answers `invalid_redirect_uri` | The agent's callback is not allowed | Add the exact URI to `MCP_EXTRA_REDIRECTS` on both hosts |
| The Allow page says "not an allowed address" but `/register` passed | The two hosts have different `MCP_EXTRA_REDIRECTS` / `MCP_BLOCKED_REDIRECT_DOMAINS` | Give both hosts the same values |
| Everyone gets "not in a group that may connect agents" | `LOGIN_CHECK` unset or wrong, the proxy's audience/issuer settings are wrong, or groups aren't in the token | Check the login check's env vars; decode the proxy's token and look for `aud`, `iss` and the groups claim; or set `MCP_DEFAULT_ROLE` |
| Clicking Allow does nothing (https callback) | CSP `form-action` blocked a redirect chain after the POST | Already handled: https callbacks get a navigation hand-off page. Check that a proxy isn't rewriting the CSP header |
| `/token` answers `invalid_grant` right after Allow | The code expired (60 s) or was used, the hosts have **different signing keys**, or `redirect_uri` differs | Same `MCP_SIGNING_KEY` on both hosts; check the clocks; check the agent sends the same `redirect_uri` |
| An agent using a metadata URL (CIMD) is refused | The document is unreachable, too big, has a different `client_id`, lists a callback that isn't allowed, or asks for a client secret | Fetch the URL yourself; check the server log line "client_id document refused" |
| People get logged out together, often | Several agent windows refresh at once with no grace window, or an old window reuses a stale refresh token after the grace window (reuse detection ends the grant) | Keep `MCP_REFRESH_GRACE_SECONDS` at about 30; look for `grant_ended reason=refresh_token_reuse` in `admin.py events`; consider `MCP_REFRESH_REUSE_ACTION=log` |
| Someone removed from the SSO group still has access | Expected until their grant ends (at most 14 days) | `admin.py revoke` for an immediate cut-off |
| The Allow page answers 503 | Signing key missing or short, or Redis unreachable (revoke list can't be checked) | Set the key; check Redis. This is the page failing safe |
