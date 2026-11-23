"""Google Cloud Identity-Aware Proxy (IAP) in front of the Allow page.

IAP signs every request with a JWT in the x-goog-iap-jwt-assertion header.

IAP's token carries the email but NOT group membership. Either give everyone who gets past IAP
one role with MCP_DEFAULT_ROLE (readonly or user, never admin; IAP's own access policy then
decides who gets in, so keep it to the people who should have that role), or look the person's
groups up here, for example with the Cloud Identity groups API
(groups.memberships.searchTransitiveGroups), and return them in Person.groups.

    IAP_AUDIENCE   /projects/<number>/global/backendServices/<id>   (load balancer)
                   or /projects/<number>/apps/<project-id>          (App Engine)
"""
from __future__ import annotations

import os
from typing import Optional

from . import Person
from ._jwt import verify

JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk"
ISSUER = "https://cloud.google.com/iap"


def person(request) -> Optional[Person]:
    audience = os.environ.get("IAP_AUDIENCE", "").strip()
    if not audience:
        return None
    claims = verify(request.headers.get("x-goog-iap-jwt-assertion", ""), jwks_url=JWKS_URL,
                    algorithms=["ES256"], audience=audience, issuer=ISSUER)
    if not claims:
        return None
    return Person(email=claims.get("email", ""), groups=())
