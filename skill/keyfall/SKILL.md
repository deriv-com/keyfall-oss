---
name: keyfall
description: Add company-SSO sign-in to a remote MCP server so people connect Claude Code, Cursor, Codex, VS Code or Gemini CLI with one URL and an Allow click, and no API keys. Uses MCP OAuth 2.1 with PKCE, Client ID Metadata Documents or dynamic client registration, an SSO-protected Allow page behind an identity-aware proxy (Cloudflare Access, Google IAP, Pomerium, oauth2-proxy), short-lived rotating tokens, roles from SSO groups, admin revoke and an audit trail. Use when building or reviewing MCP authentication, replacing MCP API keys, adding a consent page, or debugging an agent that can't connect (401 loop, redirect_uri refused, invalid_grant, Allow does nothing).
---

# Keyfall: MCP sign-in with company SSO

The reference code lives in this repo; adapt it rather than writing the flow from scratch:

| File | Use it for |
|---|---|
| `reference/mcp_server_auth.py` | the MCP server: OAuth provider, CIMD + DCR, tokens, refresh reuse detection, `caller()`, `audited()`, `build_mcp()` |
| `reference/allow_page.py` | the Allow page router (FastAPI) |
| `reference/login_check/` | "who is signed in?" per SSO setup |
| `reference/admin.py` | connections, revoke, restore, events |
| `docs/setup.md` | the steps and every setting |
| `docs/how-it-works.md` | the flow and what protects what |
| `docs/troubleshooting.md` | symptoms and fixes |
| `tests/` | the behaviour to preserve |

## The design in five lines

1. **Two hosts.** The MCP server is public and checks bearer tokens; the Allow page is behind the
   SSO proxy. Agents call the MCP server from code, so it must never sit behind an SSO login.
2. **One shared HS256 key (32+ bytes) and one Redis**, nothing else shared.
3. `/authorize` signs a **request token** (10 min) and sends the browser to the Allow page; the
   Allow page signs a **60-second code** (email, role, PKCE challenge); `/token` checks the
   code's signature, single use and PKCE, then issues a 1-hour access token and a refresh token.
4. Refresh tokens **rotate**; a 30-second grace window serves concurrent refreshes; an old token
   after that **ends the grant**; every chain ends 14 days after the Allow.
5. Roles come from **SSO groups** (exact match, highest wins) and are enforced **inside tools**.

## When adding this to a server

1. Ask which SSO setup fronts the Allow page and pick the `login_check` module (or write one that
   verifies a **signed** identity token; never trust plain `X-Forwarded-*` headers).
2. Ask which groups map to admin / user / readonly, and what each role may see in the tools.
3. Copy `mcp_server_auth.py`; register tools with `@mcp.tool(...)` + `@audited(redis)`; read the
   person with `caller()`; redact for lower roles on the server.
4. Mount `allow_page.router` in an app behind the SSO; edit `ROLE_CAN` / `CANNOT` text.
5. Same `MCP_SIGNING_KEY`, `REDIS_URL`, `MCP_REDIS_PREFIX`, `MCP_EXTRA_REDIRECTS` and
   `MCP_BLOCKED_REDIRECT_DOMAINS` on both hosts. One worker per replica for the MCP server.
6. Run `pytest -q`, then the curl checks in `docs/troubleshooting.md`.

## Rules that are easy to break

- Never put the MCP host behind the SSO proxy (agents get an HTML login page instead of JSON).
- Keep the two copies of `redirect_uri_allowed` identical (MCP server and Allow page).
- The code must carry `redirect_uri` and `redirect_uri_provided_explicitly`; the SDK compares them.
- Distinct `iss`/`aud` for the request token and the code, so neither replays as the other.
- The Allow page fails closed: no key → 503, no role → 403, bad note → 400, revoke list unreadable → 503.
- `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-store` on every Allow-page response.
- https callbacks get the meta-refresh hand-off page, not a 303 (CSP `form-action` covers redirects after a POST).
- Redis stores token **hashes** only.
- Mount the MCP app last at `/` and run its lifespan; `enable_dns_rebinding_protection=False` behind a proxy.
