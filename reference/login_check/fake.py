"""DEMO ONLY: pretends a person is signed in, so the demo runs without any SSO.

Refuses to work unless DEMO_ONLY=1 is set AND the request's Host is localhost / 127.0.0.1 / ::1.
The Host check stops DNS rebinding (a web page pointing its own name at 127.0.0.1). It is not a
network check: anyone who can reach the port can send "Host: localhost". What keeps others out is
the demo publishing its ports on 127.0.0.1 only. Never deploy this.

    FAKE_LOGIN_EMAIL    default alice@example.com
    FAKE_LOGIN_NAME     default Alice Example
    FAKE_LOGIN_GROUPS   comma-separated, default mcp-user
"""
from __future__ import annotations

import os
from typing import Optional

from . import Person

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def person(request) -> Optional[Person]:
    if os.environ.get("DEMO_ONLY") != "1" or (request.url.hostname or "") not in LOCAL_HOSTS:
        return None
    groups = os.environ.get("FAKE_LOGIN_GROUPS", "mcp-user")
    return Person(
        email=os.environ.get("FAKE_LOGIN_EMAIL", "alice@example.com"),
        name=os.environ.get("FAKE_LOGIN_NAME", "Alice Example"),
        groups=tuple(g.strip() for g in groups.split(",") if g.strip()),
    )
