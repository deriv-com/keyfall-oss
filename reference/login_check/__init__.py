"""Who is signed in? The Allow page's only dependency on your login setup.

The Allow page runs behind something that already signed the person in: an identity-aware
proxy in front of it, or your own app's session. Each module here answers one question for one
setup: "which person sent this request, and which groups are they in?"

Pick one with LOGIN_CHECK, or write your own: a module with
    def person(request) -> Person | None
that returns None whenever it is not sure. Returning None means "no Allow button".

    cloudflare_access   Cloudflare Access (Cf-Access-Jwt-Assertion header)
    google_iap          Google Cloud Identity-Aware Proxy (x-goog-iap-jwt-assertion header)
    pomerium            Pomerium (X-Pomerium-Jwt-Assertion header)
    oauth2_proxy        oauth2-proxy passing your identity provider's ID token
    fake                demo only: a pretend person on localhost
"""
from __future__ import annotations

import importlib
import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

SETUPS = ("cloudflare_access", "google_iap", "pomerium", "oauth2_proxy", "fake")


@dataclass(frozen=True)
class Person:
    email: str
    name: str = ""
    groups: tuple[str, ...] = ()


def signed_in_person(request) -> Optional[Person]:
    setup = os.environ.get("LOGIN_CHECK", "").strip()
    if setup not in SETUPS:
        logger.error("LOGIN_CHECK=%r is not one of %s: refusing every request", setup, ", ".join(SETUPS))
        return None
    module = importlib.import_module(f"{__name__}.{setup}")
    try:
        person = module.person(request)
    except Exception as exc:  # noqa: BLE001  any doubt means "not signed in"
        logger.warning("login check %s failed: %s", setup, type(exc).__name__)
        return None
    if person is None or "@" not in person.email:
        return None
    return Person(email=person.email.strip().lower(), name=person.name, groups=person.groups)
