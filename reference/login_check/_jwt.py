"""Shared helper: check a JWT that a login proxy put on the request, against its public keys."""
from __future__ import annotations

import json
import logging
from typing import Any, Iterable, Optional

import jwt  # PyJWT[crypto]

logger = logging.getLogger(__name__)
_clients: dict[str, jwt.PyJWKClient] = {}


def verify(token: str, *, jwks_url: str, algorithms: list[str], audience: Iterable[str] | str,
           issuer: Optional[str]) -> Optional[dict]:
    """Claims of a valid token, or None. Signature, expiry, audience and issuer are all checked."""
    if not token:
        return None
    client = _clients.get(jwks_url)
    if client is None:
        client = _clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=3600, timeout=5)
    try:
        key = client.get_signing_key_from_jwt(token).key
        required = ["exp", "iat", "aud"] + (["iss"] if issuer else [])
        return jwt.decode(token, key, algorithms=algorithms, audience=audience, issuer=issuer,
                          options={"require": required, "verify_iss": bool(issuer)})
    except Exception as exc:  # noqa: BLE001
        logger.warning("identity token rejected: %s", type(exc).__name__)
        return None


def groups_from(*values: Any) -> tuple[str, ...]:
    """The first non-empty group list among the given claim values (list, JSON list or CSV)."""
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            try:
                value = json.loads(text) if text.startswith("[") else text.split(",")
            except ValueError:
                value = text.split(",")
        if isinstance(value, (list, tuple)) and value:
            groups = tuple(str(g).strip() for g in value if str(g).strip())
            if groups:
                return groups
    return ()
