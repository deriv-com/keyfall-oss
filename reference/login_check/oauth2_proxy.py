"""oauth2-proxy in front of the Allow page, with any OpenID Connect identity provider.

Run oauth2-proxy with --pass-authorization-header so it forwards the provider's signed ID
token as "Authorization: Bearer <id_token>". This module checks that token against the
provider's own keys. Never trust plain X-Forwarded-Email / X-Forwarded-Groups headers: they are
not signed, and anyone who reaches the app directly can set them.

    OIDC_ISSUER        your provider's issuer URL, e.g. https://login.example.com
    OIDC_CLIENT_ID     the client ID oauth2-proxy uses (the ID token's audience)
    OIDC_JWKS_URL      optional; read from <issuer>/.well-known/openid-configuration if unset
    OIDC_GROUPS_CLAIM  claim that holds group names (default "groups")
    OIDC_ALLOW_MISSING_EMAIL_VERIFIED
                       "true" accepts tokens without an email_verified claim, for providers
                       that don't send it. By default the claim must be true.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

import httpx

from . import Person
from ._jwt import groups_from, verify

_jwks_urls: dict[str, str] = {}
_jwks_lock = threading.Lock()       # the Allow page runs in a thread pool: discover once


def _jwks_url(issuer: str) -> str:
    url = os.environ.get("OIDC_JWKS_URL", "").strip()
    if url:
        return url
    with _jwks_lock:
        if issuer not in _jwks_urls:
            conf = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=5).json()
            _jwks_urls[issuer] = conf["jwks_uri"]
        return _jwks_urls[issuer]


def person(request) -> Optional[Person]:
    issuer = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
    client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
    auth = request.headers.get("Authorization", "")
    if not issuer or not client_id or not auth.lower().startswith("bearer "):
        return None
    claims = verify(auth[7:].strip(), jwks_url=_jwks_url(issuer), algorithms=["RS256", "ES256"],
                    audience=client_id, issuer=issuer)
    if not claims:
        return None
    verified = claims.get("email_verified")       # some providers send the string "true"
    missing_ok = os.environ.get("OIDC_ALLOW_MISSING_EMAIL_VERIFIED", "").strip().lower() == "true"
    if str(verified).lower() != "true" and not (verified is None and missing_ok):
        return None
    return Person(email=claims.get("email", ""), name=str(claims.get("name") or ""),
                  groups=groups_from(claims.get(os.environ.get("OIDC_GROUPS_CLAIM", "groups"))))
