"""Demo MCP server with two tools, using reference/mcp_server_auth.py for sign-in.

    whoami        who the agent is acting for (email, role)
    get_record    one sample record; the readonly role gets it without the full body

Run by docker compose (see demo/README.md), or directly:
    PYTHONPATH=reference uvicorn demo_server:create_app --factory --app-dir demo --port 8000
"""
from __future__ import annotations

from mcp.types import ToolAnnotations

from mcp_server_auth import audited, build_mcp, caller

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                            open_world_hint=False)
FULL_ROLES = frozenset({"admin", "user"})
RECORDS = {
    "R-100": {"title": "Quarterly access review", "body": "All 42 accounts reviewed; 3 removed."},
    "R-101": {"title": "Laptop rollout", "body": "120 laptops shipped; disk encryption verified on all."},
}


def register_tools(mcp, redis) -> None:
    @mcp.tool(annotations=READ_ONLY)
    @audited(redis)
    async def whoami() -> dict:
        """Who this agent is acting for: email, name and role."""
        who = caller()
        return {"email": who["email"], "name": who["name"], "role": who["role"]}

    @mcp.tool(annotations=READ_ONLY)
    @audited(redis)
    async def get_record(record_id: str) -> dict:
        """Fetch one record by id (try R-100 or R-101). readonly sees the title only."""
        record = RECORDS.get(record_id)
        if record is None:
            return {"error": f"No record {record_id}. Try R-100 or R-101."}
        out = {"id": record_id, **record}
        if caller()["role"] not in FULL_ROLES:
            out.pop("body")
            out["body_hidden"] = "Your role (readonly) does not include record bodies."
        return out


def create_app(redis=None, **kwargs):
    _, app = build_mcp(register_tools, redis, name="demo", title="Demo App",
                       instructions="Demo data for trying sign-in. Tools: whoami, get_record.", **kwargs)
    return app
