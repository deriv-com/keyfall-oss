"""Cloudflare Access in front of the Allow page.

Access signs every request it lets through with a JWT in the Cf-Access-Jwt-Assertion header.
Groups come from your identity provider through Access; turn on group claims for the IdP in
Zero Trust, and they appear under the token's "custom" claims.

    ACCESS_TEAM_DOMAIN   <team>.cloudflareaccess.com
    ACCESS_AUD           the Access application's AUD tag (comma-separated if several)
"""
from __future__ import annotations

import os
from typing import Optional

from . import Person
from ._jwt import groups_from, verify


def person(request) -> Optional[Person]:
    team = os.environ.get("ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
    aud = [a.strip() for a in os.environ.get("ACCESS_AUD", "").split(",") if a.strip()]
    if not team or not aud:
        return None
    issuer = team if team.startswith("https://") else f"https://{team}"
    token = request.headers.get("Cf-Access-Jwt-Assertion") or request.cookies.get("CF_Authorization")
    claims = verify(token, jwks_url=f"{issuer}/cdn-cgi/access/certs", algorithms=["RS256"],
                    audience=aud, issuer=issuer)
    if not claims:
        return None
    custom = claims.get("custom") if isinstance(claims.get("custom"), dict) else {}
    return Person(
        email=claims.get("email") or custom.get("email") or "",
        name=str(claims.get("name") or custom.get("name") or ""),
        groups=groups_from(custom.get("groups"), claims.get("groups")),
    )
