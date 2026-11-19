# Connecting each agent

Every option carries **only the MCP URL**, never a secret. Below, the server is called `my-app`
and lives at `https://<mcp-host>/mcp`. The first tool call (or the client's authenticate
command) opens the browser at the Allow page.

| Agent | How |
|---|---|
| Claude Code | `claude mcp add --transport http my-app https://<mcp-host>/mcp`, then `/mcp` → Authenticate |
| Codex CLI | `codex mcp add my-app --url https://<mcp-host>/mcp` |
| Gemini CLI | `gemini mcp add --transport http my-app https://<mcp-host>/mcp` |
| Cursor | one-click deeplink (below), or add `{"mcpServers": {"my-app": {"url": "https://<mcp-host>/mcp"}}}` to `~/.cursor/mcp.json` |
| VS Code (Copilot) | one-click deeplink (below), or **MCP: Add Server** → HTTP → the URL |
| Windsurf | `{"mcpServers": {"my-app": {"serverUrl": "https://<mcp-host>/mcp"}}}` in `~/.codeium/windsurf/mcp_config.json` |

## One-click install links

Put these on an internal "Connect your agent" page:

```js
const MCP_URL = 'https://<mcp-host>/mcp';
const cursorHref = `cursor://anysphere.cursor-deeplink/mcp/install?name=my-app&config=${btoa(JSON.stringify({ url: MCP_URL }))}`;
const vscodeHref = `vscode:mcp/install?${encodeURIComponent(JSON.stringify({ name: 'my-app', type: 'http', url: MCP_URL }))}`;
```

## Where each agent sends the code back

| Agent | Callback | Allowed because |
|---|---|---|
| Claude Code, Codex, Gemini CLI, VS Code | `http://localhost:<port>/…` or `http://127.0.0.1:<port>/…` (a few versions use an https page of their vendor) | http to this computer; an https page only once its vendor's domain is in `MCP_WEB_REDIRECT_DOMAINS` |
| Cursor (desktop) | `cursor://anysphere.cursor-mcp/oauth/callback` | listed app callback (default) |
| Cursor (some versions) | `https://www.cursor.com/…`, which redirects to `cursor.com` | only once `cursor.com` is in `MCP_WEB_REDIRECT_DOMAINS`; uses the Allow page's navigation hand-off |
| Web agents (connectors in a vendor's web app) | an https page on the vendor's domain | only once the vendor's domain is in `MCP_WEB_REDIRECT_DOMAINS`. Their MCP calls come from the vendor's cloud, not the person's laptop, so list a vendor only if your data may leave that way |

If an agent is refused at `/register`, look up the `redirect_uri` it sent (it is in the MCP
server's log) and add the exact value to `MCP_EXTRA_REDIRECTS` on **both** hosts (for a website
callback, add its domain to `MCP_WEB_REDIRECT_DOMAINS` instead).

## What the person sees

1. They click the install link, or paste the command.
2. A browser tab opens on the Allow page. An SSO prompt appears only if their session expired.
3. The page names the agent, their role and what the agent will be able to do. They click **Allow**.
4. The tab hands back to the agent. It stays connected for up to 14 days, refreshing silently.
