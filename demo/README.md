# Demo: try it in 5 minutes

Runs the MCP server, the Allow page and Redis on your laptop. There is no SSO: the Allow page
uses a **demo-only fake login** that pretends you are `alice@example.com`. It only works on
`localhost` and only with `DEMO_ONLY=1`; never deploy it.

| Service | URL | Plays the part of |
|---|---|---|
| `mcp` | http://localhost:8000/mcp | your public MCP server |
| `allow` | http://localhost:8001 | your SSO-protected Allow page |
| `redis` | (internal) | shared token store |

## 1. Start it

```bash
cd demo
docker compose up --build        # or: podman compose up --build
```

## 2. Connect an agent

```bash
claude mcp add --transport http demo http://localhost:8000/mcp
```

In Claude Code run `/mcp`, choose **demo**, then **Authenticate**. Your browser opens the Allow
page; click **Allow**. Back in Claude Code, ask:

> Use the demo server's whoami tool, then get record R-100.

Other agents: see [../docs/clients.md](../docs/clients.md) and use `http://localhost:8000/mcp`.

## 3. Without an agent

```bash
python demo/smoke_test.py        # from the repo root; needs: pip install httpx
```

It walks every step an agent takes (401, discovery, register, Allow, code, tokens, a tool call)
and prints each one.

## 4. Try other roles

```bash
FAKE_LOGIN_GROUPS=mcp-readonly docker compose up -d allow
```

Connect again: the page now says **readonly**, and `get_record` hides the record body. Use
`mcp-admin`, or a group that maps to nothing (`nobody`) to see the "not in a group" page.

## 5. Revoke and watch it stop

```bash
docker compose exec mcp python /app/reference/admin.py connections
docker compose exec mcp python /app/reference/admin.py revoke alice@example.com --by you@example.com
docker compose exec mcp python /app/reference/admin.py events --limit 10
```

The agent's next call fails, and the Allow page refuses Alice until you run `restore`.

## Stop

```bash
docker compose down
```
