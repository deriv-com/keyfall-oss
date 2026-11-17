"""The Allow page: where a person approves an AI agent. Reference implementation (FastAPI).

Runs on <approval-host>, which sits behind your SSO (see login_check/). By the time a request
arrives here, the person is already signed in; login_check tells us who they are.

What it does
    GET  /connect-agent/authorize?req=<signed note>   show "Allow <agent> to use <app> as you?"
    POST /connect-agent/authorize                      Allow -> a signed 60-second code back to
                                                       the agent; Cancel -> error=access_denied
It never shows an Allow button when anything is uncertain: no key, unknown person, no group,
a bad or old signed note, or the revoke list can't be read.

Contract with the MCP server (HS256 JWTs signed with MCP_SIGNING_KEY; keep in sync with
mcp_server_auth.py):

Signed note (request token), MCP server -> here as ?req=
    iss "mcp-server", aud "mcp-connect:request", exp <= 10 min,
    client_id, client_name, client_verified, redirect_uri, redirect_uri_provided_explicitly,
    code_challenge, code_challenge_method "S256", state, scopes, resource

Code (authorization code), here -> the agent's redirect_uri as ?code=
    iss "allow-page", aud "mcp-connect:code", exp 60 s, jti (single use),
    sub (email), name, role, client_id, redirect_uri, redirect_uri_provided_explicitly,
    code_challenge, scopes, resource

Environment
    MCP_SIGNING_KEY       same value as the MCP server, at least 32 bytes
    LOGIN_CHECK           which login_check module to use (cloudflare_access, google_iap, ...)
    MCP_GROUP_ROLES       group=role pairs, highest role wins
                          (default "mcp-admin=admin,mcp-user=user,mcp-readonly=readonly")
    MCP_DEFAULT_ROLE      optional role for people with no matching group (e.g. readonly)
    MCP_APP_NAME          shown on the page (default "My App")
    MCP_REDIS_PREFIX, MCP_EXTRA_REDIRECTS, MCP_BLOCKED_REDIRECT_DOMAINS   same values as the MCP server
    REDIS_URL             the MCP server's Redis
"""
from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import logging
import os
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import jwt  # PyJWT[crypto]
import redis as redis_lib
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from login_check import signed_in_person

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/connect-agent", tags=["connect-agent"])

REQUEST_ISSUER = "mcp-server"
REQUEST_AUDIENCE = "mcp-connect:request"
CODE_ISSUER = "allow-page"
CODE_AUDIENCE = "mcp-connect:code"
CODE_TTL_SECONDS = 60
MAX_REQUEST_AGE_SECONDS = 600   # a signed note older than this is refused even if its exp is later
MIN_KEY_BYTES = 32
PREFIX = os.environ.get("MCP_REDIS_PREFIX", "keyfall:")
APP_NAME = os.environ.get("MCP_APP_NAME", "My App")

ROLE_ORDER = ("admin", "user", "readonly")  # highest first
# What each role lets an agent do. Edit to describe your own tools.
ROLE_CAN = {
    "readonly": ["Search and read records", "See summaries only; full record bodies stay hidden"],
    "user": ["Search and read records", "See full record bodies"],
    "admin": ["Search and read records", "See full record bodies", "Use admin-only tools"],
}
CANNOT = ["Change or delete anything", "Keep access past 14 days without asking you again"]


def _signing_key() -> Optional[bytes]:
    key = os.environ.get("MCP_SIGNING_KEY", "").encode()
    return key if len(key) >= MIN_KEY_BYTES else None


# --- who is this, and which role? ----------------------------------------------------------

def group_roles() -> Dict[str, str]:
    raw = os.environ.get("MCP_GROUP_ROLES", "mcp-admin=admin,mcp-user=user,mcp-readonly=readonly")
    pairs = (p.split("=", 1) for p in raw.split(",") if "=" in p)
    return {g.strip().lower(): r.strip() for g, r in pairs if r.strip() in ROLE_ORDER}


def role_for(groups) -> Optional[str]:
    """Exact (case-insensitive) group match only; the highest role wins."""
    mapping = group_roles()
    have = {mapping[g.lower()] for g in groups if g.lower() in mapping}
    for role in ROLE_ORDER:
        if role in have:
            return role
    default = os.environ.get("MCP_DEFAULT_ROLE", "").strip()
    return default if default in ROLE_ORDER else None


def current_user(request: Request) -> Optional[Dict[str, Any]]:
    person = signed_in_person(request)
    if person is None:
        return None
    role = role_for(person.groups)
    if role is None:
        return None
    return {"email": person.email, "name": person.name, "role": role}


# --- revoke + audit (the MCP server's Redis) --------------------------------------------------

_redis = None


def redis_conn():
    global _redis
    if _redis is None:
        _redis = redis_lib.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                                          decode_responses=True, socket_timeout=5, socket_connect_timeout=5)
    return _redis


def is_revoked(r, email: str) -> bool:
    return r.exists(f"{PREFIX}revoked:{email.strip().lower()}") > 0


def record_event(r, event: str, email: str, **fields: Any) -> None:
    """Never raises: auditing must not break sign-in."""
    entry = {"event": event, "email": email.strip().lower(), "ts": str(int(time.time()))}
    entry.update({k: str(v)[:2000] for k, v in fields.items() if v is not None})
    try:
        r.xadd(f"{PREFIX}audit", entry, maxlen=200_000, approximate=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit write failed: %s", exc)


# --- redirect allowlist (an identical copy lives in mcp_server_auth.py) ----------------------

LOOPBACK_HOSTS = frozenset({"localhost"})
DEFAULT_APP_REDIRECTS = ("cursor://anysphere.cursor-mcp/oauth/callback",)


def _env_set(name: str) -> frozenset:
    return frozenset(v.strip().lower() for v in os.environ.get(name, "").split(",") if v.strip())


def app_redirects() -> frozenset:
    extra = os.environ.get("MCP_EXTRA_REDIRECTS", "")
    return frozenset(DEFAULT_APP_REDIRECTS) | {u.strip() for u in extra.split(",") if u.strip()}


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def redirect_uri_allowed(uri: str) -> bool:
    """https (except blocked domains), http only back to this computer, or a listed app callback."""
    if uri in app_redirects():
        return True
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if parts.fragment or not parts.hostname:
        return False
    host = parts.hostname.lower().rstrip(".")   # "example.com." is the same host as "example.com"
    if any(host == d or host.endswith("." + d) for d in _env_set("MCP_BLOCKED_REDIRECT_DOMAINS")):
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and _is_loopback(host)


# --- the two tokens ------------------------------------------------------------------------

def verify_request_token(token: str, key: bytes) -> Dict[str, Any]:
    """Check the MCP server's signed note. Raises ValueError with a reason that is safe to show."""
    try:
        claims = jwt.decode(token, key, algorithms=["HS256"], audience=REQUEST_AUDIENCE, issuer=REQUEST_ISSUER,
                            options={"require": ["exp", "iat", "aud", "iss"]})
    except jwt.ExpiredSignatureError:
        raise ValueError("This sign-in link has expired.")
    except jwt.PyJWTError:
        raise ValueError("This sign-in link is not valid.")
    if time.time() - float(claims["iat"]) > MAX_REQUEST_AGE_SECONDS:
        raise ValueError("This sign-in link has expired.")
    for field in ("client_id", "redirect_uri", "code_challenge"):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise ValueError("This sign-in link is missing information.")
    if claims.get("code_challenge_method") != "S256":
        raise ValueError("This agent did not use a supported sign-in method.")
    if not redirect_uri_allowed(claims["redirect_uri"]):
        raise ValueError("This agent asked to return to an address that is not allowed.")
    scopes = claims.get("scopes") or []
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise ValueError("This sign-in link is not valid.")
    return claims


def issue_code(user: Dict[str, Any], rc: Dict[str, Any], key: bytes) -> str:
    """The one-time code: who approved, as which role, for which agent and PKCE challenge."""
    now = int(time.time())
    return jwt.encode({
        "iss": CODE_ISSUER, "aud": CODE_AUDIENCE, "iat": now, "exp": now + CODE_TTL_SECONDS,
        "jti": secrets.token_urlsafe(24),
        "sub": user["email"], "name": user.get("name") or "", "role": user["role"],
        "client_id": rc["client_id"],
        "redirect_uri": rc["redirect_uri"],
        "redirect_uri_provided_explicitly": bool(rc.get("redirect_uri_provided_explicitly", True)),
        "code_challenge": rc["code_challenge"],
        "scopes": rc.get("scopes") or [],
        "resource": rc.get("resource"),
    }, key, algorithm="HS256")


def csrf_token(email: str, req: str, key: bytes) -> str:
    """Ties the Allow form to this person and this signed note."""
    return hmac.new(key, f"connect-agent\n{email.lower()}\n{req}".encode(), hashlib.sha256).hexdigest()


def with_query(uri: str, **params: Optional[str]) -> str:
    """Append params, keeping any query the redirect URI already has."""
    p = urlsplit(uri)
    q = parse_qsl(p.query, keep_blank_values=True) + [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def _is_web_callback(uri: str) -> bool:
    p = urlsplit(uri)
    return p.scheme == "https" and not _is_loopback(p.hostname or "")


def _form_origin(uri: str) -> str:
    """CSP form-action source for the return address. App schemes -> 'scheme:'.
    https -> both the www. and bare forms, because vendor callbacks bounce between them."""
    p = urlsplit(uri)
    if p.scheme not in ("http", "https"):
        return f"{p.scheme}:"
    origin = f"{p.scheme}://{p.netloc}"
    host = p.hostname or ""
    if p.scheme == "https" and not _is_loopback(host) and "." in host:
        alt = host[4:] if host.startswith("www.") else f"www.{host}"
        origin += f" https://{alt}{':' + str(p.port) if p.port else ''}"
    return origin


# --- pages -----------------------------------------------------------------------------------

_CSS = """
/* Brand: coral #FF444F and slate #181C25. Change these to restyle the page. */
:root{--bg:#f5f6f8;--card:#fff;--ink:#181C25;--muted:#5f6672;--line:#e3e6eb;--accent:#FF444F;
 --accent-ink:#fff;--ok:#11744a;--ok-bg:#e6f5ed;--warn:#8a5a00;--warn-bg:#fff3d6;--chip:#fff0f1;
 --chip-ink:#c9222d;--no:#c9222d}
@media (prefers-color-scheme:dark){:root{--bg:#14171f;--card:#1e222c;--ink:#f5f6f8;--muted:#a3aab8;
 --line:#2b303c;--accent:#FF444F;--accent-ink:#fff;--ok:#5bd49a;--ok-bg:#12281d;--warn:#f2c47a;
 --warn-bg:#2a2214;--chip:#2a1e24;--chip-ink:#ff7a82;--no:#ff7a82}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px 16px;color:var(--ink);
 background:radial-gradient(900px 480px at 50% -12%,color-mix(in srgb,var(--accent) 16%,transparent),transparent),var(--bg);
 font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.card{width:100%;max-width:470px;background:var(--card);border:1px solid var(--line);border-radius:18px;
 padding:28px 26px;box-shadow:0 1px 2px rgba(16,24,40,.05),0 18px 48px rgba(16,24,40,.10)}
.pair{display:flex;align-items:center;justify-content:center;gap:12px;margin:0 0 18px}
.tile{width:54px;height:54px;border-radius:15px;display:grid;place-items:center;font-size:22px;font-weight:700;
 background:var(--chip);color:var(--chip-ink);border:1px solid var(--line)}
.tile.app{background:var(--accent);color:var(--accent-ink);border-color:transparent}
.wire{position:relative;width:76px;height:2px;
 background:repeating-linear-gradient(90deg,var(--line) 0 6px,transparent 6px 11px)}
.wire svg{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);background:var(--card);
 padding:0 5px;width:26px;height:16px;color:var(--muted)}
.eyebrow{text-align:center;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:650}
h1{font-size:21px;line-height:1.3;margin:6px 0 10px;text-align:center;letter-spacing:-.01em}
.who{display:flex;justify-content:center;margin:0 0 18px}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;padding:3px 10px;border-radius:999px;font-weight:550}
.badge svg{width:13px;height:13px}
.ok{background:var(--ok-bg);color:var(--ok)}.warn{background:var(--warn-bg);color:var(--warn)}
dl{display:grid;grid-template-columns:auto 1fr;gap:9px 16px;margin:0 0 18px;padding:14px 16px;
 border:1px solid var(--line);border-radius:12px;font-size:14px}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.role{display:inline-block;padding:1px 10px;border-radius:999px;background:var(--chip);color:var(--chip-ink);font-size:13px;font-weight:650}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 6px}
ul{list-style:none;margin:0 0 14px;padding:0;font-size:14px}
li{display:flex;gap:10px;align-items:flex-start;padding:3px 0}
li svg{flex:0 0 16px;width:16px;height:16px;margin-top:3px}
.can svg{color:var(--ok)}.cannot svg{color:var(--no)}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px}
button,.button{font:inherit;font-size:15px;font-weight:650;border-radius:11px;padding:11px 16px;cursor:pointer;
 border:1px solid var(--line);background:transparent;color:var(--ink);text-align:center;text-decoration:none;display:block}
.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button:hover,.button:hover{filter:brightness(1.06)}
button:focus-visible,.button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.note{margin:16px 0 0;font-size:12.5px;color:var(--muted);text-align:center}
.big{display:block;width:46px;height:46px;margin:0 auto 8px}
.big.bad{color:var(--no)}.big.go{color:var(--accent)}
p{margin:0 0 12px;text-align:center;color:var(--muted)}
.spin{width:22px;height:22px;margin:4px auto 14px;border:3px solid var(--line);border-top-color:var(--accent);
 border-radius:50%;animation:s .9s linear infinite}@keyframes s{to{transform:rotate(1turn)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none}}
"""

_ICON = {
    "check": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
             'stroke-linejoin="round" aria-hidden="true"><path d="M3 8.5l3.2 3L13 4.5"/></svg>',
    "x": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
         'aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8"/></svg>',
    "lock": '<svg viewBox="0 0 24 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
            '<rect x="7" y="6.5" width="10" height="8" rx="1.8"/><path d="M9.5 6.5V4.6a2.5 2.5 0 015 0v1.9"/></svg>',
    "shield": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" '
              'aria-hidden="true"><path d="M8 1.8l5 1.9v3.9c0 3.1-2.1 5.4-5 6.6-2.9-1.2-5-3.5-5-6.6V3.7z"/>'
              '<path d="M5.6 8.2l1.7 1.6 3.1-3.3"/></svg>',
    "info": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">'
            '<circle cx="8" cy="8" r="6.2"/><path d="M8 7.2v4M8 4.8v.1" stroke-linecap="round"/></svg>',
    "stop": '<svg class="big bad" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" '
            'aria-hidden="true"><circle cx="24" cy="24" r="20"/><path d="M16 16l16 16M32 16L16 32" stroke-linecap="round"/></svg>',
    "go": '<svg class="big go" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" '
          'aria-hidden="true"><circle cx="24" cy="24" r="20"/><path d="M15 25l6 6 12-13" stroke-linecap="round" '
          'stroke-linejoin="round"/></svg>',
}


def _page(title: str, body: str, status: int = 200, form_origin: Optional[str] = None) -> HTMLResponse:
    form_action = "'self'" + (f" {form_origin}" if form_origin else "")
    doc = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
           "<meta name=\"color-scheme\" content=\"light dark\">"
           f"<title>{html.escape(title)} · {html.escape(APP_NAME)}</title><style>{_CSS}</style></head>"
           f"<body><main class=\"card\">{body}</main></body></html>")
    return HTMLResponse(doc, status_code=status, headers={
        # A consent page must never be framed (clickjacking), cached or leak its URL onward.
        "Content-Security-Policy": (f"default-src 'none'; style-src 'unsafe-inline'; form-action {form_action}; "
                                    "frame-ancestors 'none'; base-uri 'none'"),
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    })


def _error(message: str, status: int) -> HTMLResponse:
    e = html.escape
    return _page("Can't connect", (
        f"{_ICON['stop']}<div class=\"eyebrow\">{e(APP_NAME)} · connect an agent</div>"
        f"<h1>Can't connect this agent</h1><p>{e(message)}</p>"
        "<p>Go back to your agent and start the connection again.</p>"), status)


def _initial(text: str) -> str:
    return html.escape((text.strip()[:1] or "?").upper())


def _identity_badge(rc: Dict[str, Any]) -> str:
    """How sure we are about the agent's name.

    A metadata-document (CIMD) client_id proves who published the name, but not who is using it:
    any app on this laptop can start a sign-in with a well-known vendor's client_id and its own
    localhost listener. Only an https callback on the vendor's own domain ties the code to the
    vendor, so only that gets "Verified".
    """
    e = html.escape
    if not rc.get("client_verified"):
        return f"<span class=\"badge warn\">{_ICON['info']}Name given by the agent itself</span>"
    vendor = (urlsplit(rc["client_id"]).hostname or "").lower()
    p = urlsplit(rc["redirect_uri"])
    host = (p.hostname or "").lower()
    if p.scheme == "https" and vendor and (host == vendor or host.endswith("." + vendor)):
        return f"<span class=\"badge ok\">{_ICON['shield']}Verified by {e(vendor)}</span>"
    return (f"<span class=\"badge warn\">{_ICON['info']}Published by {e(vendor)}; "
            "an app on this computer can't be confirmed</span>")


def _consent(user: Dict[str, Any], rc: Dict[str, Any], req: str, key: bytes, action: str) -> HTMLResponse:
    e = html.escape
    agent = (rc.get("client_name") or "").strip() or "An unnamed agent"
    uri = rc["redirect_uri"]
    host = (urlsplit(uri).hostname or "").lower()
    dest = "an app on this computer" if (_is_loopback(host) or uri in app_redirects()) else host
    badge = _identity_badge(rc)
    can = "".join(f"<li>{_ICON['check']}<span>{e(t)}</span></li>" for t in ROLE_CAN[user["role"]])
    cannot = "".join(f"<li>{_ICON['x']}<span>{e(t)}</span></li>" for t in CANNOT)
    body = (
        f"<div class=\"pair\"><div class=\"tile\" title=\"{e(agent)}\">{_initial(agent)}</div>"
        f"<div class=\"wire\">{_ICON['lock']}</div>"
        f"<div class=\"tile app\" title=\"{e(APP_NAME)}\">{_initial(APP_NAME)}</div></div>"
        f"<div class=\"eyebrow\">{e(APP_NAME)} · connect an agent</div>"
        f"<h1>Allow {e(agent)} to use {e(APP_NAME)} as you?</h1>"
        f"<div class=\"who\">{badge}</div>"
        "<dl>"
        f"<dt>Signed in as</dt><dd>{e(user['email'])}</dd>"
        f"<dt>Your role</dt><dd><span class=\"role\">{e(user['role'])}</span></dd>"
        f"<dt>Returns to</dt><dd>{e(dest)}</dd>"
        "<dt>Lasts</dt><dd>Up to 14 days. You or an admin can end it any time.</dd>"
        "</dl>"
        f"<h2>It will be able to</h2><ul class=\"can\">{can}</ul>"
        f"<h2>It will not</h2><ul class=\"cannot\">{cannot}</ul>"
        f"<form method=\"post\" action=\"{e(action)}\">"
        f"<input type=\"hidden\" name=\"req\" value=\"{e(req)}\">"
        f"<input type=\"hidden\" name=\"csrf\" value=\"{csrf_token(user['email'], req, key)}\">"
        "<div class=\"actions\">"
        "<button type=\"submit\" name=\"decision\" value=\"deny\">Cancel</button>"
        "<button class=\"primary\" type=\"submit\" name=\"decision\" value=\"allow\" autofocus>Allow</button>"
        "</div></form>"
        "<p class=\"note\">Only allow an agent you started yourself, just now.</p>"
    )
    return _page("Connect an agent", body, form_origin=_form_origin(uri))


def _continue(agent: str, target: str) -> HTMLResponse:
    """Web callbacks: hand off by navigation, not a 303 from the POST.
    CSP form-action also covers redirects after a form POST, and vendor callbacks keep hopping
    hosts, so the browser blocks the 303 and Allow looks like it did nothing."""
    e = html.escape
    return _page("Returning to agent", (
        f"<meta http-equiv=\"refresh\" content=\"0;url={e(target)}\">{_ICON['go']}"
        f"<h1>Returning to {e(agent)}…</h1><div class=\"spin\" role=\"status\" aria-label=\"Loading\"></div>"
        f"<a class=\"button primary\" href=\"{e(target)}\">Continue</a>"))


def _revoked_response(r, user: Dict[str, Any], rc: Optional[Dict[str, Any]]) -> Optional[HTMLResponse]:
    """Fails closed: if the revoke list can't be read, nobody gets an Allow button."""
    try:
        if not is_revoked(r, user["email"]):
            return None
    except Exception as exc:  # noqa: BLE001
        logger.error("revoke check failed for %s: %s", user["email"], exc)
        return _error("Agent access can't be checked right now. Try again in a few minutes.", 503)
    record_event(r, "connect_blocked", user["email"], role=user["role"], client_id=(rc or {}).get("client_id"))
    return _error("An admin has turned off agent access for your account.", 403)


# --- routes ------------------------------------------------------------------------------

def _gate(request: Request, req: str):
    """Common checks for GET and POST. Returns (key, user, signed note) or an error page."""
    key = _signing_key()
    if key is None:
        logger.error("MCP_SIGNING_KEY is unset or shorter than 32 bytes")
        return _error("Agent connections are not set up yet.", 503)
    user = current_user(request)
    if user is None:
        return _error("Your account is not in a group that may connect agents.", 403)
    try:
        rc = verify_request_token(req, key)
    except ValueError as exc:
        return _error(str(exc), 400)
    return key, user, rc


@router.get("/authorize")
async def authorize_page(request: Request, req: str = ""):
    gate = _gate(request, req)
    if isinstance(gate, HTMLResponse):
        return gate
    key, user, rc = gate
    blocked = _revoked_response(redis_conn(), user, rc)
    return blocked or _consent(user, rc, req, key, action=request.url.path)


@router.post("/authorize")
async def authorize_decision(request: Request, req: str = Form(""), csrf: str = Form(""),
                             decision: str = Form("")):
    gate = _gate(request, req)
    if isinstance(gate, HTMLResponse):
        return gate
    key, user, rc = gate
    if not hmac.compare_digest(csrf, csrf_token(user["email"], req, key)):
        return _error("This approval form is not valid. Start the connection again.", 400)
    r = redis_conn()
    blocked = _revoked_response(r, user, rc)
    if blocked is not None:
        return blocked

    state = rc.get("state")
    agent = rc.get("client_name") or rc["client_id"]
    event = dict(role=user["role"], client_id=rc["client_id"], client_name=rc.get("client_name"))
    if decision != "allow":
        record_event(r, "connect_declined", user["email"], **event)
        target = with_query(rc["redirect_uri"], error="access_denied", state=state)
    else:
        record_event(r, "connect_allowed", user["email"], **event)
        target = with_query(rc["redirect_uri"], code=issue_code(user, rc, key), state=state)
    if _is_web_callback(rc["redirect_uri"]):
        return _continue(agent, target)
    return RedirectResponse(target, status_code=303, headers={"Cache-Control": "no-store"})
