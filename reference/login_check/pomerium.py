"""Pomerium in front of the Allow page.

Pomerium signs every request with a JWT in the X-Pomerium-Jwt-Assertion header (enable
"pass_identity_headers" on the route). Its public keys are on the route itself.

    POMERIUM_ROUTE_HOST  the Allow page's host as Pomerium serves it, e.g. approve.example.com
                         (the token's audience; keys at https://<host>/.well-known/pomerium/jwks.json)
    POMERIUM_ISSUER      optional: the expected "iss" claim, checked when set
"""
from __future__ import annotations

import os
from typing import Optional

from . import Person
from ._jwt import groups_from, verify


def person(request) -> Optional[Person]:
    host = os.environ.get("POMERIUM_ROUTE_HOST", "").strip()
    if not host:
        return None
    claims = verify(request.headers.get("X-Pomerium-Jwt-Assertion", ""),
                    jwks_url=f"https://{host}/.well-known/pomerium/jwks.json", algorithms=["ES256"],
                    audience=host, issuer=os.environ.get("POMERIUM_ISSUER") or None)
    if not claims:
        return None
    return Person(email=claims.get("email", ""), name=str(claims.get("name") or ""),
                  groups=groups_from(claims.get("groups")))
