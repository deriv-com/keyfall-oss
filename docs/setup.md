# Setting it up for your own MCP server

You need: a Python MCP server (MCP SDK 2.x) you want to protect, a host behind your SSO (an
internal portal or admin site is ideal), and a Redis both can reach.

## 1. Pick the two hosts

| Host | Example | Behind SSO? |
|---|---|---|
| MCP server | `mcp.example.com` | **No.** Public (or VPN-only), but never behind the SSO proxy |
| Allow page | `portal.example.com` | **Yes** |

## 2. Generate one signing key

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Store it in your secret manager and give the **same value** to both hosts as `MCP_SIGNING_KEY`.
Rotating it only invalidates sign-ins in flight (signed notes and codes); issued tokens are
random strings and keep working.

## 3. The Allow page

Add the router to an app that already sits behind your SSO:

```python
from fastapi import FastAPI
from allow_page import router          # reference/allow_page.py + reference/login_check/

app = FastAPI()
app.include_router(router)            # serves /connect-agent/authorize
```

Then pick the login check that matches your setup and set its variables:

| `LOGIN_CHECK` | Your setup | Set | Groups |
|---|---|---|---|
| `cloudflare_access` | Cloudflare Access | `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | turn on group claims for your identity provider in Zero Trust; they arrive under `custom.groups` |
| `google_iap` | Google Cloud IAP | `IAP_AUDIENCE` | not in IAP's token: use `MCP_DEFAULT_ROLE`, or look groups up in your directory inside `google_iap.py` |
| `pomerium` | Pomerium | `POMERIUM_ROUTE_HOST` (`POMERIUM_ISSUER` optional) | the `groups` claim; enable identity headers on the route |
| `oauth2_proxy` | oauth2-proxy with any OpenID Connect provider | `OIDC_ISSUER`, `OIDC_CLIENT_ID` (`OIDC_JWKS_URL`, `OIDC_GROUPS_CLAIM` optional) | the provider's groups claim; run oauth2-proxy with `--pass-authorization-header` |

Something else (your app's own session, another proxy)? Write a module in `login_check/` with
`def person(request) -> Person | None` and return `None` whenever you're not sure. Only trust
identity that is **signed** (a JWT checked against the proxy's public keys), never plain
`X-Forwarded-Email`-style headers.

Map groups to roles, highest first wins, exact match only:

```bash
MCP_GROUP_ROLES="mcp-admin=admin,mcp-user=user,mcp-readonly=readonly"
MCP_DEFAULT_ROLE=            # optional, e.g. readonly, for setups without groups
MCP_APP_NAME="My App"        # shown on the page
```

Edit `ROLE_CAN` and `CANNOT` at the top of `allow_page.py` so the page describes what *your*
tools let each role do.

## 4. The MCP server

Copy `reference/mcp_server_auth.py` next to your server and register your tools through it:

```python
from mcp.types import ToolAnnotations
from mcp_server_auth import audited, build_mcp, caller

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)

def register_tools(mcp, redis):
    @mcp.tool(annotations=READ_ONLY)
    @audited(redis)                       # one audit event per call
    async def get_record(record_id: str) -> dict:
        who = caller()                    # {"email", "name", "role", "client_id"}
        record = load(record_id)          # your backend
        if who["role"] == "readonly":
            record.pop("body")            # enforce roles on the server, never via the prompt
        return record

mcp, app = build_mcp(register_tools, name="my-app", title="My App",
                     instructions="What your tools do, for the agent.")
```

Serve `app` with **one worker per replica** (MCP sessions live in memory), for example
`uvicorn server:app --workers 1`. To add it to an existing FastAPI app instead, see the comment
at the end of `mcp_server_auth.py`: mount it last at `/` and run its lifespan.

Environment:

```bash
MCP_ISSUER_URL=https://mcp.example.com
MCP_ALLOW_PAGE_URL=https://portal.example.com/connect-agent/authorize
MCP_SCOPE=mcp
```

Client ID Metadata Documents: `/authorize` is reachable by anyone, and a `client_id` that is an
https URL makes the server download it. The download accepts only port 443 and printable ASCII
URLs, refuses private addresses (also when wrapped in IPv6, such as NAT64), redirects, compressed
bodies and anything over 10 KB, gives up after 5 seconds in total, and connects to the exact
address it checked (so DNS rebinding can't swap in an internal one). In production, also set
`MCP_CIMD_TRUSTED_HOSTS` to the vendors your people use, so the server only ever fetches from them. Agents using a metadata URL from any
other host are refused (they don't fall back to `/register` on their own); if that's a problem,
set `MCP_CIMD_ENABLED=false` so the server stops offering CIMD and every agent uses `/register`.

Website callbacks: `/register` is open, so anyone can register an agent whose callback is their
own website, then send a person a link to the Allow page. If that person clicks **Allow**, the
code goes to that website, and its owner can redeem it (they chose the PKCE secret). So websites
receive codes only when their domain is listed in `MCP_WEB_REDIRECT_DOMAINS`, for example
`cursor.com` (a domain covers its subdomains). Most agents return to `localhost` or an app
callback, which need no listing. `*` allows any https site, leaving the Allow page (which names
the site) as the only check; avoid it.

Audit trail: `@audited` records each tool call's arguments (up to 2,000 characters per field).
If a tool takes a secret or personal data as an argument, leave it out of the record.

## 5. Infrastructure

- The MCP host must answer `/mcp`, `/.well-known/*`, `/register`, `/authorize`, `/token` and
  `/revoke` itself; no SSO proxy, no login page in front of them.
- Reverse proxy: `proxy_buffering off`, `proxy_http_version 1.1`, `proxy_read_timeout 300s`, and
  forward `Host` and `X-Forwarded-Proto`. Buffering breaks streaming responses.
- Redis: both hosts, same `REDIS_URL` and `MCP_REDIS_PREFIX`. Use TLS (`rediss://`) across networks,
  and a password. Set `maxmemory-policy noeviction` (or a `volatile-*` policy): an `allkeys-*`
  policy lets Redis evict revoke flags and used-code markers when it fills up, and `/register`
  is open to anyone.
- Rate-limit `/register`, `/authorize` and `/token` per client IP at the proxy. They are public
  and unauthenticated by design; the server caps what one call can store or fetch, not how many
  calls arrive.
- Optional: per-person rate limits on tool calls, in the same Redis (count calls per email per
  window inside `audited`).

## 6. Configuration reference

| Variable | MCP server | Allow page | Default |
|---|---|---|---|
| `MCP_SIGNING_KEY` | ✓ | ✓ (same value) | required, 32+ bytes |
| `REDIS_URL` | ✓ | ✓ (same Redis) | `redis://localhost:6379/0` |
| `MCP_REDIS_PREFIX` | ✓ | ✓ (same value) | `keyfall:` |
| `MCP_EXTRA_REDIRECTS` | ✓ | ✓ (same value) | none (Cursor's app callback is built in) |
| `MCP_BLOCKED_REDIRECT_DOMAINS` | ✓ | ✓ (same value) | none |
| `MCP_WEB_REDIRECT_DOMAINS` | ✓ | ✓ (same value) | none: no websites (`*` = any https site; see "Website callbacks") |
| `MCP_ISSUER_URL` | ✓ | | `https://mcp.example.com` |
| `MCP_ALLOW_PAGE_URL` | ✓ | | `https://portal.example.com/connect-agent/authorize` |
| `MCP_SCOPE` | ✓ | | `mcp` |
| `MCP_REFRESH_GRACE_SECONDS` | ✓ | | `30` (max 120) |
| `MCP_REFRESH_REUSE_ACTION` | ✓ | | `end_grant` (`log` only records; any other value ends the grant) |
| `MCP_CIMD_ENABLED` | ✓ | | `true` |
| `MCP_CIMD_TRUSTED_HOSTS` | ✓ | | any public host |
| `LOGIN_CHECK` + its variables | | ✓ | required |
| `MCP_GROUP_ROLES` | | ✓ | `mcp-admin=admin,mcp-user=user,mcp-readonly=readonly` |
| `MCP_DEFAULT_ROLE` | | ✓ | none |
| `MCP_APP_NAME` | | ✓ | `My App` |

## 7. Admin

```bash
python admin.py connections                       # who has an agent connected
python admin.py revoke alice@example.com --by you@example.com
python admin.py restore alice@example.com --by you@example.com
python admin.py events --limit 50                 # sign-ins, revokes, tool calls
```

## 8. Before you ship

- `pytest -q` passes.
- The curl checks in [troubleshooting.md](troubleshooting.md) answer as expected.
- Connect with two agents (one using a localhost callback, e.g. Claude Code; one using an app
  callback, e.g. Cursor), call a tool, refresh (wait an hour or revoke and reconnect), and
  revoke with `admin.py`.
- Someone outside the SSO groups gets no Allow button.
