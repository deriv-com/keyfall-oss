"""MCP server side: the OAuth authorization server, the /mcp endpoint and the token store.

Reference implementation for the MCP Python SDK (mcp 2.x). Copy it into your MCP server and
adapt the marked parts. It runs on the PUBLIC host (<mcp-host>). The person's approval
happens on a separate, SSO-protected host (<approval-host>, see allow_page.py).

Flow
1. Discovery: /mcp without a token answers 401 and points the agent at
   /.well-known/oauth-protected-resource/mcp and /.well-known/oauth-authorization-server.
2. The agent identifies itself: Client ID Metadata Document (a client_id that is an https URL,
   see CIMD below) or Dynamic Client Registration (POST /register).
3. /authorize (the SDK) -> authorize(): sign a "request token" (the signed note) and send the
   browser to the Allow page.
4. The Allow page signs a 60-second "code" (email, role, PKCE challenge) and returns it to the
   agent's redirect_uri.
5. /token (the SDK checks PKCE and redirect_uri) -> load_authorization_code() checks the
   code's signature and that it is used once -> exchange_authorization_code() issues tokens.
6. /mcp: every call needs a bearer token; load_access_token() checks it and the revoke flag.
7. Refresh: every use rotates the refresh token. Reusing an old refresh token after the short
   grace window ends the whole grant (stolen-token detection).

Tokens are random strings. Redis keeps only their SHA-256, never the tokens themselves.

Environment
    MCP_SIGNING_KEY            shared with the Allow page, at least 32 bytes
    MCP_ISSUER_URL             https://<mcp-host>
    MCP_ALLOW_PAGE_URL         https://<approval-host>/connect-agent/authorize
    MCP_SCOPE                  OAuth scope for this server (default "mcp")
    MCP_REDIS_PREFIX           key prefix shared with the Allow page (default "keyfall:")
    MCP_EXTRA_REDIRECTS        comma-separated extra app callbacks (same value on both hosts)
    MCP_BLOCKED_REDIRECT_DOMAINS  comma-separated domains an approval may never return to
    MCP_REFRESH_GRACE_SECONDS  concurrent-refresh grace window (default 30, max 120)
    MCP_REFRESH_REUSE_ACTION   "end_grant" (default) or "log" when an old refresh token comes back
    MCP_CIMD_ENABLED           accept Client ID Metadata Documents (default true)
    MCP_CIMD_TRUSTED_HOSTS     optional comma-separated hosts allowed to serve them
    REDIS_URL                  redis://host:6379/0 (rediss:// for TLS)
"""
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import time
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import jwt  # PyJWT
import redis.asyncio as aioredis
from cryptography.fernet import Fernet, InvalidToken
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    RequestBodyLimitMiddleware,
    TransportSecuritySettings,
)
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from redis.exceptions import WatchError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, request_response

logger = logging.getLogger(__name__)

# --- contract with the Allow page (keep in sync with allow_page.py) -----------------------
REQUEST_ISSUER = "mcp-server"
REQUEST_AUDIENCE = "mcp-connect:request"
CODE_ISSUER = "allow-page"
CODE_AUDIENCE = "mcp-connect:code"
REQUEST_TTL_SECONDS = 600            # the signed note: time to sign in and click Allow
ROLES = frozenset({"admin", "user", "readonly"})
MIN_KEY_BYTES = 32
PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")   # base64url(SHA-256(verifier)), no padding

ACCESS_TTL_SECONDS = 3600            # 1 hour
GRANT_TTL_SECONDS = 14 * 24 * 3600   # a chain of refresh tokens never outlives the Allow by more than this
CLIENT_TTL_SECONDS = 90 * 24 * 3600  # a registered (DCR) agent is kept 90 days
# /register is open to anyone: keep what one registration can store small.
MAX_REDIRECT_URIS, MAX_REDIRECT_URI_LENGTH, MAX_CLIENT_RECORD_BYTES = 10, 2000, 8192
CODE_USED_TTL_SECONDS = 300          # remembers used codes well past their 60 s life
REFRESH_GRACE_SECONDS = min(max(int(os.environ.get("MCP_REFRESH_GRACE_SECONDS", "30")), 0), 120)
# A rotated refresh token used again after the grace window: "end_grant" ends the whole chain
# (the thief and the person both lose it; the person clicks Allow again), "log" only records it.
REFRESH_REUSE_ACTION = os.environ.get("MCP_REFRESH_REUSE_ACTION", "end_grant")

PREFIX = os.environ.get("MCP_REDIS_PREFIX", "keyfall:")
SCOPE = os.environ.get("MCP_SCOPE", "mcp")
ISSUER_URL = os.environ.get("MCP_ISSUER_URL", "https://mcp.example.com").rstrip("/")
RESOURCE_URL = f"{ISSUER_URL}/mcp"
ALLOW_PAGE_URL = os.environ.get("MCP_ALLOW_PAGE_URL", "https://portal.example.com/connect-agent/authorize")
AUDIT_STREAM = f"{PREFIX}audit"
AUDIT_MAXLEN = 200_000


def signing_key() -> bytes:
    key = os.environ.get("MCP_SIGNING_KEY", "").encode()
    if len(key) < MIN_KEY_BYTES:
        raise RuntimeError("MCP_SIGNING_KEY is unset or shorter than 32 bytes")
    return key


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _norm(email: str) -> str:
    return (email or "").strip().lower()


def _env_set(name: str) -> frozenset:
    return frozenset(v.strip().lower() for v in os.environ.get(name, "").split(",") if v.strip())


def display_name(name: Optional[str], limit: int = 80) -> str:
    """An agent's self-chosen name, safe to show: no control or bidi characters, one line, short."""
    text = "".join(c if c.isprintable() else " " for c in (name or ""))
    return " ".join(text.split())[:limit]


def _grace_fernet(refresh_token: str) -> Fernet:
    """Cipher keyed by the rotated refresh token itself, which is never stored."""
    digest = hashlib.sha256(b"mcp-refresh-grace:" + refresh_token.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


async def is_revoked(redis, email: str) -> bool:
    return bool(await redis.exists(f"{PREFIX}revoked:{_norm(email)}"))


async def record_event(redis, event: str, email: str, **fields: Any) -> None:
    """Append one event to the audit stream. Never raises: auditing must not break sign-in."""
    entry = {"event": event, "email": _norm(email), "ts": str(int(time.time()))}
    entry.update({k: str(v)[:2000] for k, v in fields.items() if v is not None})
    try:
        await redis.xadd(AUDIT_STREAM, entry, maxlen=AUDIT_MAXLEN, approximate=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit write failed: %s", exc)


# --- redirect allowlist (an identical copy lives in allow_page.py) ------------------------
LOOPBACK_HOSTS = frozenset({"localhost"})
# Desktop agents that return through their own URL scheme instead of a localhost listener.
DEFAULT_APP_REDIRECTS = ("cursor://anysphere.cursor-mcp/oauth/callback",)


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
    # One reading for every parser: no spaces, control or non-ASCII characters, backslashes,
    # user:pass@ or fragments. Python reads "http://evil.com\\@127.0.0.1/" as 127.0.0.1; a browser
    # reads it as evil.com.
    if not uri.isascii() or any(c <= " " or c in "\x7f\\#" for c in uri):
        return False
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if not parts.hostname or "@" in parts.netloc:
        return False
    host = parts.hostname.lower().rstrip(".")   # "example.com." is the same host as "example.com"
    if any(host == d or host.endswith("." + d) for d in _env_set("MCP_BLOCKED_REDIRECT_DOMAINS")):
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and _is_loopback(host)


# --- Client ID Metadata Documents (CIMD) ---------------------------------------------------
# The client_id is an https URL the agent's vendor hosts; it serves a small JSON document with
# the agent's name and redirect_uris. No /register call, nothing stored per laptop, and the
# name on the Allow page is vouched for by the vendor's domain.

CIMD_ENABLED = os.environ.get("MCP_CIMD_ENABLED", "true").lower() != "false"
CIMD_MAX_BYTES = 10_000
CIMD_TIMEOUT_SECONDS = 5
CIMD_MIN_CACHE_SECONDS, CIMD_DEFAULT_CACHE_SECONDS, CIMD_MAX_CACHE_SECONDS = 60, 3600, 86400


class CimdClient(OAuthClientInformationFull):
    """A client described by a metadata document.

    Loopback redirect URIs match on any port (RFC 8252 section 7.3): a document cannot know
    which free port the agent's listener will get on each laptop.
    """

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        try:
            return super().validate_redirect_uri(redirect_uri)
        except InvalidRedirectUriError:
            if redirect_uri is None or redirect_uri.scheme != "http" or not _is_loopback(redirect_uri.host or ""):
                raise
            for listed in self.redirect_uris or []:
                if (listed.scheme == "http" and listed.host == redirect_uri.host
                        and (listed.path or "/") == (redirect_uri.path or "/")):
                    return redirect_uri
            raise


def is_cimd_client_id(client_id: str) -> bool:
    return client_id.startswith("https://")


def _cimd_url_ok(url: str) -> bool:
    """https on the default port, a real path, no credentials, query or fragment, not an IP literal.

    Printable ASCII only: urlsplit silently drops tabs and newlines, so without this a client_id
    could carry control characters (log forging, terminal escapes) or look-alike letters.
    """
    if not url.isascii() or any(c <= " " or c in "\x7f\\" for c in url):
        return False
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return False
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        return False
    if port not in (None, 443):    # the server's own address must not become a port scanner
        return False
    if p.hostname.endswith("."):   # one spelling per host, so trusted-host and cache keys can't be dodged
        return False
    if p.path in ("", "/") or "/." in p.path:
        return False
    try:
        ipaddress.ip_address(p.hostname)
        return False
    except ValueError:
        pass
    trusted = _env_set("MCP_CIMD_TRUSTED_HOSTS")
    return not trusted or p.hostname.lower() in trusted


_NAT64 = ipaddress.ip_network("64:ff9b::/96")              # RFC 6052: IPv6 for an IPv4 address
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")            # deprecated ::a.b.c.d form


def _public_address(ip: str) -> bool:
    """A global unicast address, also when it is an IPv4 address wrapped in IPv6 (NAT64 etc.)."""
    addr = ipaddress.ip_address(ip)
    if not addr.is_global or addr.is_multicast:
        return False
    if addr.version == 6:
        inner = addr.ipv4_mapped or addr.sixtofour or (addr.teredo or (None, None))[1]
        if inner is None and (addr in _NAT64 or addr in _IPV4_COMPATIBLE):
            inner = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if inner is not None and (not inner.is_global or inner.is_multicast):
            return False
    return True


async def _pinned_address(host: str, port: int) -> Optional[str]:
    """Resolve once; return an address to connect to, or None if any answer is not public.

    Every answer must be a public address (no private, loopback, link-local, multicast or
    reserved ranges). The download then connects to this exact address, so a DNS server can't
    answer "public" for the check and "internal" for the connection (DNS rebinding).
    """
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    ips = sorted({info[4][0] for info in infos})
    if not all(_public_address(ip) for ip in ips):
        return None
    return ips[0] if ips else None


async def fetch_client_document(url: str) -> tuple[dict, int]:
    """Download a metadata document. Returns (document, cache seconds). Raises ValueError.

    Connects to the address that was checked, with the real hostname as Host and as the TLS
    server name, so the certificate is still verified for the vendor's domain. The whole download
    (DNS, connect, every byte) has one deadline: httpx's timeout is per read, so a server sending
    a byte every few seconds would otherwise hold the request for hours. The body is read as
    sent and must not be compressed, so the size cap counts the bytes that reach memory.
    """
    p = urlsplit(url)
    port = p.port or 443
    try:
        async with asyncio.timeout(CIMD_TIMEOUT_SECONDS):
            ip = await _pinned_address(p.hostname, port)
            if ip is None:
                raise ValueError("client_id host is not public")
            pinned = urlunsplit(("https", f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}", p.path, "", ""))
            headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Host": p.netloc}
            async with httpx.AsyncClient(timeout=CIMD_TIMEOUT_SECONDS, follow_redirects=False) as http:
                async with http.stream("GET", pinned, headers=headers,
                                       extensions={"sni_hostname": p.hostname}) as resp:
                    if resp.status_code != 200:
                        raise ValueError(f"client_id document answered {resp.status_code}")
                    if resp.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
                        raise ValueError("client_id document is compressed")
                    body = b""
                    async for chunk in resp.aiter_raw():
                        body += chunk
                        if len(body) > CIMD_MAX_BYTES:
                            raise ValueError("client_id document is too large")
                    cache = CIMD_DEFAULT_CACHE_SECONDS
                    for part in resp.headers.get("cache-control", "").split(","):
                        name, _, value = part.strip().partition("=")
                        if name.lower() == "max-age" and value.isdigit():
                            cache = int(value)
    except TimeoutError:
        raise ValueError("client_id document took too long") from None
    try:
        doc = json.loads(body)
    except ValueError:
        raise ValueError("client_id document is not JSON")
    return doc, min(max(cache, CIMD_MIN_CACHE_SECONDS), CIMD_MAX_CACHE_SECONDS)


def client_from_document(url: str, doc: Any) -> CimdClient:
    """Check a metadata document and turn it into a client. Raises ValueError."""
    if not isinstance(doc, dict) or doc.get("client_id") != url:
        raise ValueError("document client_id does not match its URL")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        raise ValueError("document has no redirect_uris")
    if not all(redirect_uri_allowed(u) for u in uris):
        raise ValueError("document lists a redirect_uri that is not allowed")
    method = doc.get("token_endpoint_auth_method", "none")
    if method != "none":  # a public document cannot carry a secret; private_key_jwt is not supported here
        raise ValueError(f"token_endpoint_auth_method {method!r} is not supported")
    name = doc.get("client_name")
    client = CimdClient(
        client_id=url,
        client_name=display_name(name) if isinstance(name, str) else None,
        client_uri=doc.get("client_uri") if isinstance(doc.get("client_uri"), str) else None,
        redirect_uris=uris,
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
    )
    # Check again as stored: parsing normalizes URLs (a backslash becomes a slash, so what Python
    # read as a loopback address can be another host to a browser).
    if not all(redirect_uri_allowed(str(u)) for u in client.redirect_uris or []):
        raise ValueError("document lists a redirect_uri that is not allowed")
    return client


# --- provider ----------------------------------------------------------------------------

class AppAuthCode(AuthorizationCode):
    jti: str
    role: str
    name: str = ""


class AppRefreshToken(RefreshToken):
    role: str
    name: str = ""
    grant_id: str
    grant_expires_at: int


class AppAccessToken(AccessToken):
    role: str
    name: str = ""
    grant_id: str = ""


class AllowPageOAuthProvider:
    """OAuth authorization server whose consent step is the Allow page on another host.

    Redis keys (PREFIX + ...):
        client:<id>            DCR client (90 days)
        cimd:<sha256(url)>     cached metadata document
        code-used:<jti>        a code that was exchanged (5 minutes)
        grant:<id>             hash: one Allow = one chain of tokens. subject, role, name,
                               client_id, client_name, connected_at, grant_expires_at,
                               access, refresh (current token hashes). Expires with the grant.
                               Every token is checked against it: deleting it ends them all.
        access:<sha256>        access token record (1 hour)
        refresh:<sha256>       refresh token record (until the grant ends)
        refresh-grace:<sha256> a just-rotated refresh token, for concurrent refreshes (30 s)
        refresh-used:<sha256>  a rotated refresh token -> its grant id (reuse detection)
        revoked:<email>        set by an admin: everything for this person is refused
        audit                  stream of events
    """

    def __init__(self, redis, *, resource_url: str, allow_page_url: str,
                 fetch_document: Callable[[str], Any] = fetch_client_document):
        self.redis = redis
        self.resource_url = resource_url
        self.allow_page_url = allow_page_url
        self.fetch_document = fetch_document

    # clients ---------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        if is_cimd_client_id(client_id):
            return await self._cimd_client(client_id) if CIMD_ENABLED else None
        raw = await self.redis.get(f"{PREFIX}client:{client_id}")
        return OAuthClientInformationFull.model_validate_json(raw) if raw else None

    async def _cimd_client(self, url: str) -> Optional[CimdClient]:
        if not _cimd_url_ok(url):
            return None
        key = f"{PREFIX}cimd:{_hash(url)}"
        cached = await self.redis.get(key)
        try:
            if cached:
                return client_from_document(url, json.loads(cached))
            doc, cache_seconds = await self.fetch_document(url)
            client = client_from_document(url, doc)
        except (ValueError, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.warning("client_id document refused %r: %s", url, exc)
            return None
        await self.redis.set(key, json.dumps(doc), ex=cache_seconds)
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "At least one redirect_uri is required")
        if len(uris) > MAX_REDIRECT_URIS or any(len(u) > MAX_REDIRECT_URI_LENGTH for u in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                f"At most {MAX_REDIRECT_URIS} redirect_uris of up to {MAX_REDIRECT_URI_LENGTH} characters",
            )
        if any(not redirect_uri_allowed(u) for u in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect_uri must be https, http to localhost, or a supported app callback",
            )
        record = client_info.model_dump_json()
        if len(record) > MAX_CLIENT_RECORD_BYTES:
            raise RegistrationError("invalid_client_metadata", "Client metadata is too large")
        await self.redis.set(f"{PREFIX}client:{client_info.client_id}", record, ex=CLIENT_TTL_SECONDS)

    # approval hand-off -----------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Return the URL the SDK redirects the browser to: the Allow page, with a signed note."""
        redirect_uri = str(params.redirect_uri)
        if not redirect_uri_allowed(redirect_uri):
            raise AuthorizeError("invalid_request", "redirect_uri is not allowed")
        if params.resource and params.resource.rstrip("/") != self.resource_url.rstrip("/"):
            raise AuthorizeError("invalid_target", "Unknown resource")
        if not PKCE_CHALLENGE.fullmatch(params.code_challenge or ""):
            raise AuthorizeError("invalid_request", "code_challenge must be an S256 challenge (43 base64url characters)")
        now = int(time.time())
        req = jwt.encode(
            {
                "iss": REQUEST_ISSUER,
                "aud": REQUEST_AUDIENCE,
                "iat": now,
                "exp": now + REQUEST_TTL_SECONDS,
                "client_id": client.client_id,
                "client_name": display_name(client.client_name),
                # The Allow page shows the vendor's domain for metadata-document clients;
                # a DCR client's name is only what the agent said about itself.
                "client_verified": is_cimd_client_id(client.client_id),
                "redirect_uri": redirect_uri,
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "code_challenge": params.code_challenge,
                "code_challenge_method": "S256",
                "state": params.state,
                "scopes": [SCOPE],
                "resource": self.resource_url,
            },
            signing_key(),
            algorithm="HS256",
        )
        return f"{self.allow_page_url}?{urlencode({'req': req})}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AppAuthCode]:
        """Check the Allow page's signed code. The SDK then checks PKCE and redirect_uri."""
        try:
            claims = jwt.decode(
                authorization_code,
                signing_key(),
                algorithms=["HS256"],
                audience=CODE_AUDIENCE,
                issuer=CODE_ISSUER,
                options={"require": ["exp", "iat", "aud", "iss", "jti", "sub"]},
            )
        except jwt.PyJWTError as exc:
            logger.warning("code rejected: %s", type(exc).__name__)
            return None
        if claims.get("client_id") != client.client_id or claims.get("role") not in ROLES:
            return None
        if await self.redis.exists(f"{PREFIX}code-used:{claims['jti']}"):
            return None
        if await is_revoked(self.redis, claims["sub"]):
            return None
        return AppAuthCode(
            code=authorization_code,
            scopes=[SCOPE],
            expires_at=float(claims["exp"]),
            client_id=client.client_id,
            code_challenge=claims["code_challenge"],
            redirect_uri=claims["redirect_uri"],
            redirect_uri_provided_explicitly=bool(claims.get("redirect_uri_provided_explicitly", True)),
            resource=self.resource_url,
            subject=claims["sub"],
            jti=claims["jti"],
            role=claims["role"],
            name=claims.get("name") or "",
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AppAuthCode
    ) -> OAuthToken:
        # Atomic single use: the second exchange of the same code loses the SET NX.
        if not await self.redis.set(f"{PREFIX}code-used:{authorization_code.jti}", "1",
                                    nx=True, ex=CODE_USED_TTL_SECONDS):
            raise TokenError("invalid_grant", "Authorization code already used")
        now = int(time.time())
        grant_id = secrets.token_urlsafe(16)
        grant_expires_at = now + GRANT_TTL_SECONDS
        key = f"{PREFIX}grant:{grant_id}"
        pipe = self.redis.pipeline(transaction=True)
        pipe.hset(key, mapping={
            "subject": authorization_code.subject, "role": authorization_code.role,
            "name": authorization_code.name, "client_id": client.client_id,
            "client_name": display_name(client.client_name), "connected_at": str(now),
            "grant_expires_at": str(grant_expires_at),
        })
        pipe.expireat(key, grant_expires_at)
        await pipe.execute()
        tokens = await self._issue(client.client_id, authorization_code.subject, authorization_code.role,
                                   authorization_code.name, grant_id, grant_expires_at)
        # An admin revoke that landed after load_authorization_code read the flag may have looked
        # for grants before this one existed. Check again now that it does: either we see the
        # flag here, or the revoke's search starts after this point and finds this grant.
        if await is_revoked(self.redis, authorization_code.subject):
            await self.end_grant(grant_id, reason="revoked")
            raise TokenError("invalid_grant", "Agent access is turned off for this account")
        await record_event(self.redis, "connected", authorization_code.subject, role=authorization_code.role,
                           client_id=client.client_id, client_name=display_name(client.client_name),
                           grant=grant_id)
        return tokens

    # tokens ----------------------------------------------------------------------------

    async def _issue(self, client_id: str, subject: str, role: str, name: str,
                     grant_id: str, grant_expires_at: int) -> OAuthToken:
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        access_ttl = min(ACCESS_TTL_SECONDS, grant_expires_at - now)
        refresh_ttl = grant_expires_at - now
        if access_ttl <= 0:
            raise TokenError("invalid_grant", "Approval expired")
        base = {"client_id": client_id, "subject": subject, "role": role, "name": name, "grant": grant_id}
        gkey = f"{PREFIX}grant:{grant_id}"
        # The grant is the source of truth. If it ended while this request was in flight (reuse
        # detection, revoke), write nothing: WATCH turns "is it still there?" and the writes into
        # one step, so a grant that was just deleted is never re-created by a late refresh.
        async with self.redis.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(gkey)
                if not await pipe.hexists(gkey, "subject"):
                    raise TokenError("invalid_grant", "Approval ended")
                pipe.multi()
                pipe.set(f"{PREFIX}access:{_hash(access)}",
                         json.dumps({**base, "expires_at": now + access_ttl, "refresh": _hash(refresh)}),
                         ex=access_ttl)
                pipe.set(f"{PREFIX}refresh:{_hash(refresh)}",
                         json.dumps({**base, "grant_expires_at": grant_expires_at, "access": _hash(access)}),
                         ex=refresh_ttl)
                pipe.hset(gkey, mapping={"access": _hash(access), "refresh": _hash(refresh)})
                await pipe.execute()
            except WatchError:
                raise TokenError("invalid_grant", "Approval ended") from None
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=access_ttl,
                          scope=SCOPE, refresh_token=refresh)

    async def _grant_live(self, grant_id: Optional[str]) -> bool:
        """Every token is checked against its grant, so ending the grant ends them all at once."""
        return bool(grant_id) and bool(await self.redis.hexists(f"{PREFIX}grant:{grant_id}", "subject"))

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[AppRefreshToken]:
        h = _hash(refresh_token)
        raw = await self.redis.get(f"{PREFIX}refresh:{h}")
        if not raw:  # rotated a moment ago by a concurrent refresh: accepted within the grace window
            raw = await self._await_grace(h)
        if not raw:
            # Rotated longer ago than the grace window: two parties hold this chain, so one of
            # them stole it. We can't tell which, so the whole grant ends (RFC 9700 4.14.2).
            grant_id = await self.redis.get(f"{PREFIX}refresh-used:{h}")
            if grant_id:
                await self._refresh_reused(grant_id)
            return None
        rec = json.loads(raw)
        if rec["client_id"] != client.client_id or await is_revoked(self.redis, rec["subject"]):
            return None
        if not await self._grant_live(rec.get("grant")):
            return None
        return AppRefreshToken(
            token=refresh_token, client_id=rec["client_id"], scopes=[SCOPE],
            expires_at=rec["grant_expires_at"], resource=self.resource_url, subject=rec["subject"],
            role=rec["role"], name=rec.get("name") or "", grant_id=rec["grant"],
            grant_expires_at=rec["grant_expires_at"],
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: AppRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        old = _hash(refresh_token.token)
        raw = await self.redis.getdel(f"{PREFIX}refresh:{old}")
        if not raw:  # already rotated by a concurrent refresh, or revoked
            reused = await self._grace_pair(refresh_token.token, client.client_id)
            if reused is not None:
                return reused
            raise TokenError("invalid_grant", "Refresh token is no longer valid")
        rec = json.loads(raw)
        await self.redis.delete(f"{PREFIX}access:{rec['access']}")
        # Same grant_expires_at: rotation never extends the approval.
        new = await self._issue(client.client_id, refresh_token.subject, refresh_token.role,
                                refresh_token.name, refresh_token.grant_id, refresh_token.grant_expires_at)
        remaining = max(refresh_token.grant_expires_at - int(time.time()), 1)
        await self.redis.set(f"{PREFIX}refresh-used:{old}", refresh_token.grant_id, ex=remaining)
        if REFRESH_GRACE_SECONDS > 0:
            sealed = _grace_fernet(refresh_token.token).encrypt(new.model_dump_json().encode()).decode()
            await self.redis.set(f"{PREFIX}refresh-grace:{old}", json.dumps({**rec, "issued": sealed}),
                                 ex=REFRESH_GRACE_SECONDS)
        return new

    async def _grace_pair(self, old_token: str, client_id: str) -> Optional[OAuthToken]:
        """The pair a just-rotated refresh token was exchanged for, while still in grace."""
        raw = await self._await_grace(_hash(old_token))
        if not raw:
            return None
        rec = json.loads(raw)
        if rec.get("client_id") != client_id or await is_revoked(self.redis, rec["subject"]):
            return None
        if not await self._grant_live(rec.get("grant")):
            return None
        try:
            issued = _grace_fernet(old_token).decrypt(rec["issued"].encode())
        except (InvalidToken, KeyError, AttributeError):
            return None
        return OAuthToken.model_validate_json(issued)

    async def _await_grace(self, old_hash: str, wait_s: float = 0.5) -> Optional[str]:
        """Grace record for a rotated refresh token, polling briefly for a concurrent writer."""
        key = f"{PREFIX}refresh-grace:{old_hash}"
        for _ in range(int(wait_s / 0.05) + 1):
            raw = await self.redis.get(key)
            if raw or REFRESH_GRACE_SECONDS <= 0:
                return raw
            await asyncio.sleep(0.05)
        return None

    async def _refresh_reused(self, grant_id: str) -> None:
        if REFRESH_REUSE_ACTION == "end_grant":
            await self.end_grant(grant_id, reason="refresh_token_reuse")
            return
        subject = await self.redis.hget(f"{PREFIX}grant:{grant_id}", "subject") or ""
        logger.warning("rotated refresh token reused for %s (grant %s), action=log", subject, grant_id)
        await record_event(self.redis, "refresh_reuse", subject, grant=grant_id)

    async def end_grant(self, grant_id: str, *, reason: str) -> bool:
        """Delete a grant and its live tokens. The agent must be allowed again."""
        key = f"{PREFIX}grant:{grant_id}"
        g = await self.redis.hgetall(key)
        if not g:
            return False
        await self.redis.delete(key, f"{PREFIX}access:{g.get('access')}", f"{PREFIX}refresh:{g.get('refresh')}")
        logger.warning("grant ended (%s) for %s client %s", reason, g.get("subject"), g.get("client_id"))
        await record_event(self.redis, "grant_ended", g.get("subject", ""), reason=reason,
                           client_id=g.get("client_id"), client_name=g.get("client_name"), grant=grant_id)
        return True

    async def load_access_token(self, token: str) -> Optional[AppAccessToken]:
        raw = await self.redis.get(f"{PREFIX}access:{_hash(token)}")
        if not raw:
            return None
        rec = json.loads(raw)
        if not await self._grant_live(rec.get("grant")) or await is_revoked(self.redis, rec["subject"]):
            return None
        return AppAccessToken(
            token=token, client_id=rec["client_id"], scopes=[SCOPE], expires_at=rec["expires_at"],
            resource=self.resource_url, subject=rec["subject"], claims={"role": rec["role"]},
            role=rec["role"], name=rec.get("name") or "", grant_id=rec.get("grant", ""),
        )

    async def revoke_token(self, token: Any) -> None:
        """The agent disconnects itself (POST /revoke): end the grant behind the token."""
        kind = "access" if isinstance(token, AppAccessToken) else "refresh"
        raw = await self.redis.get(f"{PREFIX}{kind}:{_hash(token.token)}")
        grant_id = json.loads(raw).get("grant") if raw else getattr(token, "grant_id", "")
        if grant_id:
            await self.end_grant(grant_id, reason="agent_revoked")
        await self.redis.delete(f"{PREFIX}{kind}:{_hash(token.token)}", f"{PREFIX}refresh-grace:{_hash(token.token)}")


# --- tools: who is calling, and an audit trail -------------------------------------------

def caller() -> dict:
    """The signed-in person behind this tool call: email, name, role, client_id."""
    tok = get_access_token()
    if tok is None:  # /mcp always requires a token; this is a safety net
        raise ToolError("Not signed in")
    return {
        "email": tok.subject or "",
        "name": getattr(tok, "name", "") or "",
        "role": getattr(tok, "role", None) or (tok.claims or {}).get("role", ""),
        "client_id": tok.client_id,
    }


def audited(redis) -> Callable:
    """Decorator: write one tool_call event per call (who, tool, args, outcome, duration).

        @mcp.tool()
        @audited(redis)
        async def my_tool(...): ...
    """
    def wrap(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def tool(*args: Any, **kwargs: Any) -> Any:
            who, start, status = caller(), time.monotonic(), "ok"
            try:
                return await fn(*args, **kwargs)
            except Exception as exc:
                status = f"error {type(exc).__name__}"
                raise
            finally:
                await record_event(redis, "tool_call", who["email"], role=who["role"],
                                   client_id=who["client_id"], tool=fn.__name__,
                                   args=json.dumps(kwargs, default=str), status=status,
                                   ms=int((time.monotonic() - start) * 1000))
        return tool
    return wrap


# --- wiring ------------------------------------------------------------------------------

def redis_client() -> aioredis.Redis:
    return aioredis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True,
                             socket_timeout=5, socket_connect_timeout=5)


def _no_open_redirect(handler: Callable[[Request], Any], allow_page_url: str) -> Callable[[Request], Any]:
    """/authorize, but an error is shown here instead of being sent on to a website.

    The SDK sends /authorize errors (a bad scope, a missing parameter, a refused resource) to the
    client's redirect_uri. Anyone can register a client with an https redirect_uri, so that turns
    this public host into an open redirector: a link to it lands on any site, with no click and
    no sign-in (RFC 9700 section 4.11.2). Errors still go back to an agent listening on this
    computer or an app callback; only website callbacks get the error as a 400 here.
    """
    async def authorize(request: Request) -> Response:
        resp = await handler(request)
        location = resp.headers.get("location", "")
        if not (300 <= resp.status_code < 400) or not location or location.startswith(f"{allow_page_url}?"):
            return resp
        p = urlsplit(location)
        if p.scheme not in ("http", "https") or (p.scheme == "http" and _is_loopback((p.hostname or "").lower())):
            return resp
        q = dict(parse_qsl(p.query))
        body = {k: q[k] for k in ("error", "error_description", "state") if k in q}
        return JSONResponse(body or {"error": "invalid_request"}, status_code=400, headers={"Cache-Control": "no-store"})
    return authorize


def build_mcp(register_tools: Callable[[MCPServer, Any], None], redis=None, *, name: str = "my-app",
              title: str = "My App", instructions: str = "", fetch_document=fetch_client_document):
    """Build the MCP server and its Starlette app (serve it with ONE worker per replica).

    register_tools(mcp, redis) adds your tools; use caller() and audited(redis) inside them.
    """
    redis = redis if redis is not None else redis_client()
    provider = AllowPageOAuthProvider(redis, resource_url=RESOURCE_URL, allow_page_url=ALLOW_PAGE_URL,
                                      fetch_document=fetch_document)
    registration = ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE])
    revocation = RevocationOptions(enabled=True)
    mcp = MCPServer(
        name=name,
        title=title,
        instructions=instructions,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=ISSUER_URL,
            resource_server_url=RESOURCE_URL,
            validate_token_resource=True,
            required_scopes=[SCOPE],
            client_registration_options=registration,
            revocation_options=revocation,
        ),
    )
    register_tools(mcp, redis)
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        # A public server behind a proxy; DNS-rebinding protection is for localhost-only servers.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    # Ahead of the SDK's own /authorize route: same handler, but its errors never send the
    # browser on to a website (see _no_open_redirect).
    authorize = request_response(_no_open_redirect(AuthorizationHandler(provider).handle, ALLOW_PAGE_URL))
    app.router.routes.insert(0, Route("/authorize", RequestBodyLimitMiddleware(authorize, DEFAULT_MAX_REQUEST_BODY_SIZE),
                                      methods=["GET", "POST"]))
    if CIMD_ENABLED:
        # The SDK's metadata does not advertise CIMD yet. Serve the same document with the flag
        # set, ahead of the SDK's own route, so agents that support it skip /register.
        metadata = build_metadata(mcp.settings.auth.issuer_url, None, registration, revocation)
        metadata.client_id_metadata_document_supported = True
        body = metadata.model_dump(mode="json", exclude_none=True)

        async def as_metadata(_: Request) -> JSONResponse:
            return JSONResponse(body, headers={"Cache-Control": "public, max-age=3600",
                                               "Access-Control-Allow-Origin": "*"})

        app.router.routes.insert(0, Route("/.well-known/oauth-authorization-server", as_metadata,
                                          methods=["GET"]))
    return mcp, app


# --- mounting inside an existing FastAPI app ------------------------------------------------
#
#   _mcp, _mcp_app = build_mcp(register_tools)
#
#   @asynccontextmanager
#   async def lifespan(_app):
#       # The session manager runs only inside its app's lifespan; a mount does not start it.
#       async with _mcp_app.router.lifespan_context(_mcp_app):
#           yield
#
#   app = FastAPI(lifespan=lifespan)
#   app.include_router(...)        # your own routes first
#   app.mount("/", _mcp_app)       # last: /mcp, /register, /authorize, /token, /revoke, /.well-known/*
