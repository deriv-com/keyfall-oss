"""Small admin tool for the MCP server's sign-ins. Reads and writes the same Redis.

    python admin.py connections [--email alice@example.com]
    python admin.py revoke  alice@example.com --by you@example.com
    python admin.py restore alice@example.com --by you@example.com
    python admin.py events  [--limit 30] [--email alice@example.com]

Revoke takes effect at once: the person's tokens are deleted, and the revoke flag makes the MCP
server refuse any token, refresh or code for them, and the Allow page refuse new approvals,
until it is restored. Being removed from the SSO group alone ends access when the grant ends
(at most 14 days); revoke is the immediate cut-off.

Environment: REDIS_URL, MCP_REDIS_PREFIX (same values as the MCP server).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis as redis_lib

PREFIX = os.environ.get("MCP_REDIS_PREFIX", "keyfall:")
AUDIT_STREAM = f"{PREFIX}audit"


def _norm(email: str) -> str:
    return (email or "").strip().lower()


def _record(r, event: str, email: str, **fields: Any) -> None:
    entry = {"event": event, "email": _norm(email), "ts": str(int(time.time()))}
    entry.update({k: str(v)[:2000] for k, v in fields.items() if v is not None})
    r.xadd(AUDIT_STREAM, entry, maxlen=200_000, approximate=True)


def list_connections(r, email: Optional[str] = None) -> List[Dict[str, Any]]:
    """One row per connected agent (a live grant), newest first."""
    rows = []
    for key in r.scan_iter(match=f"{PREFIX}grant:*", count=500):
        g = r.hgetall(key)
        if not g or (email and _norm(g.get("subject", "")) != _norm(email)):
            continue
        rows.append({
            "email": _norm(g.get("subject", "")), "role": g.get("role", ""),
            "agent": g.get("client_name") or g.get("client_id", ""),
            "connected_at": int(g.get("connected_at") or 0), "ends_at": int(g.get("grant_expires_at") or 0),
            "grant": key[len(f"{PREFIX}grant:"):],
        })
    return sorted(rows, key=lambda x: x["connected_at"], reverse=True)


def revoke(r, email: str, by: str) -> int:
    """Turn off agent access for this person now. Returns how many agents were disconnected."""
    email = _norm(email)
    r.set(f"{PREFIX}revoked:{email}", json.dumps({"by": _norm(by), "at": int(time.time())}))
    ended = 0
    for row in list_connections(r, email):
        g = r.hgetall(f"{PREFIX}grant:{row['grant']}")
        r.delete(f"{PREFIX}grant:{row['grant']}", f"{PREFIX}access:{g.get('access')}",
                 f"{PREFIX}refresh:{g.get('refresh')}")
        ended += 1
    _record(r, "revoked", email, actor=by, agents=ended)
    return ended


def restore(r, email: str, by: str) -> bool:
    """Let this person connect agents again (they click Allow again)."""
    removed = r.delete(f"{PREFIX}revoked:{_norm(email)}") > 0
    _record(r, "restored", email, actor=by)
    return removed


def recent_events(r, limit: int = 30, email: Optional[str] = None) -> List[Dict[str, str]]:
    out = []
    for _, fields in r.xrevrange(AUDIT_STREAM, count=limit * (20 if email else 1)):
        if email and fields.get("email") != _norm(email):
            continue
        out.append(fields)
        if len(out) >= limit:
            break
    return out


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("connections", help="who has an agent connected")
    c.add_argument("--email")
    for name in ("revoke", "restore"):
        p = sub.add_parser(name, help=f"{name} a person's agent access")
        p.add_argument("email")
        p.add_argument("--by", required=True, help="your own email, for the audit trail")
    e = sub.add_parser("events", help="recent sign-in, revoke and tool-call events")
    e.add_argument("--limit", type=int, default=30)
    e.add_argument("--email")
    args = ap.parse_args(argv)

    r = redis_lib.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    if args.cmd == "connections":
        rows = list_connections(r, args.email)
        for x in rows:
            print(f"{x['email']:<32} {x['role']:<9} {x['agent'][:28]:<28} "
                  f"since {_when(x['connected_at'])}  ends {_when(x['ends_at'])}")
        print(f"{len(rows)} connected agent(s)")
    elif args.cmd == "revoke":
        print(f"Revoked {_norm(args.email)}: {revoke(r, args.email, args.by)} agent(s) disconnected.")
    elif args.cmd == "restore":
        print(f"Restored {_norm(args.email)}." if restore(r, args.email, args.by)
              else f"{_norm(args.email)} was not revoked.")
    else:
        for ev in recent_events(r, args.limit, args.email):
            extra = " ".join(f"{k}={v}" for k, v in ev.items() if k not in ("event", "email", "ts") and v)
            print(f"{_when(int(ev.get('ts', 0)))}  {ev.get('event', ''):<17} {ev.get('email', ''):<30} {extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
