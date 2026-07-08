# ZeroPath MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Interact with ZeroPath security findings via MCP-compatible tools.

This MCP server calls ZeroPath tRPC V2 procedures directly (no REST wrappers) and returns structured JSON responses suitable for agent consumption.

---

## Blog Post

Learn more about why we built this and how it fits into the evolving AI development ecosystem:

**[Chat With Your AppSec Scans: Introducing the ZeroPath MCP Server](https://zeropath.com/blog/chat-with-your-appsec-scans)**

## Installation

### Quick Install (Recommended)

Install directly from GitHub:

```bash
# Using pip
pip install git+https://github.com/ZeroPathAI/zeropath-mcp-server.git

# Using uvx (run without installing)
uvx --from git+https://github.com/ZeroPathAI/zeropath-mcp-server zeropath-mcp-server
```

You can also pin to a specific version:

```bash
# Specific version tag
pip install git+https://github.com/ZeroPathAI/zeropath-mcp-server.git@v0.1.0

# Latest from main branch
uvx --from "git+https://github.com/ZeroPathAI/zeropath-mcp-server@main" zeropath-mcp-server
```

### From Source

```bash
git clone https://github.com/ZeroPathAI/zeropath-mcp-server.git
cd zeropath-mcp-server
uv sync
```

### From PyPI (Optional)

If the package is published to PyPI, you can also install via:

```bash
pip install zeropath-mcp-server
```

---

## Setup

### 1. Generate API Key

Generate a user-scoped or admin API key from ZeroPath Settings.

### 2. Configure Environment Variables

```bash
export ZEROPATH_BASE_URL="https://zeropath.com"  # optional (defaults to https://zeropath.com)
export ZEROPATH_TOKEN_ID=your_token_id
export ZEROPATH_TOKEN_SECRET=your_token_secret
export ZEROPATH_ORG_ID=your_org_id
```

Use `ZEROPATH_BASE_URL` to target staging or another environment, for example:

```bash
export ZEROPATH_BASE_URL="https://staging.branch.zeropath.com"
```

---

## Configuration

Add the following to your MCP config file (Claude Desktop, Cursor, etc.):

### Using GitHub URL (Recommended)

```json
{
  "mcpServers": {
    "zeropath": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/ZeroPathAI/zeropath-mcp-server",
        "zeropath-mcp-server"
      ],
      "env": {
        "ZEROPATH_BASE_URL": "https://zeropath.com",
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

### Using source install

```json
{
  "mcpServers": {
    "zeropath": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/path/to/zeropath-mcp-server",
        "python",
        "-m",
        "zeropath_mcp_server"
      ],
      "env": {
        "ZEROPATH_BASE_URL": "https://zeropath.com",
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

### Using PyPI install (Optional)

```json
{
  "mcpServers": {
    "zeropath": {
      "command": "zeropath-mcp-server",
      "env": {
        "ZEROPATH_BASE_URL": "https://zeropath.com",
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

---

## Tool Surface (tRPC V2)

Tools are loaded dynamically from the ZeroPath frontend's MCP manifest at startup.

All tool calls use tRPC V2 procedures directly using tRPC v10 HTTP conventions:
- Queries: `GET /trpc/<procedure>?input=<url-encoded-json>`
- Mutations: `POST /trpc/<procedure>` with the raw JSON input object as the body (not wrapped).

Successful responses are returned as structured JSON with the `{ "result": { "data": ... } }` wrapper removed. Errors return the tRPC `error` object directly.

The server also performs best-effort client-side input validation using each tool's `inputSchema` from the manifest and returns a `BAD_REQUEST` error before calling tRPC when inputs are invalid. If a schema uses unsupported JSON Schema features, client-side validation is skipped for that call (server-side validation remains authoritative).

In addition to the manifest-driven tools, the server exposes a small set of hardcoded **Security Compass (SD Elements)** tools (see below). These talk to ZeroPath's internal tRPC surface rather than the REST v2 manifest, using the same credentials.

---

## Example Calls

List issues:

```json
{
  "tool": "issues.list",
  "input": {
    "page": 1,
    "pageSize": 25,
    "statuses": ["PENDING_REVIEW"],
    "sortBy": "score",
    "sortOrder": "desc"
  }
}
```

Archive issues:

```json
{
  "tool": "issues.archive",
  "input": {
    "issueIds": ["issue_123", "issue_456"],
    "reason": "Confirmed duplicate"
  }
}
```

Create a rule:

```json
{
  "tool": "rules.create",
  "input": {
    "name": "Detect unsafe eval",
    "rule": "Detect any use of eval() on user input",
    "globPattern": "**/*.js",
    "sourceTypes": ["FILE_HANDLER"],
    "repositoryIds": ["repo_123"]
  }
}
```

Fetch stats summary:

```json
{
  "tool": "stats.summary",
  "input": {
    "organizationId": "org_123"
  }
}
```

---

## Security Compass (SD Elements) Tools

Tools for ZeroPath's [Security Compass / SD Elements integration](https://docs.zeropath.com/integrations/security-compass): link SD Elements projects to ZeroPath repositories, sync countermeasures into scanning rules, and review coverage.

> **Note:** Connecting the integration — supplying the SD Elements base URL and API token — and rotating that token are done in the ZeroPath dashboard (**Settings → Integrations → Security Compass**), never through these tools. API keys should not pass through an AI agent. The tools below operate on the connection saved in the dashboard.

### `security_compass_get_integration()`

Read the Security Compass integration configured for the organization, including all project-to-repository mappings and their latest sync status.

**Parameters:** None

**Prompt example:**
> "Show me the Security Compass integration configured for my ZeroPath organization."

### `security_compass_test_connection(sde_base_url, sde_project_id)`

Validate the dashboard-saved SD Elements credentials against a specific project. Returns the countermeasure count on success.

**Parameters:**
- `sde_base_url` (required): Base URL of the SD Elements tenant
- `sde_project_id` (required): SD Elements project ID to probe

**Prompt example:**
> "Test my Security Compass connection against project 8."

### `security_compass_add_project_mapping(sde_project_id, repository_id)`

Link an SD Elements project to a ZeroPath repository.

**Parameters:**
- `sde_project_id` (required): SD Elements project ID
- `repository_id` (required): ZeroPath repository ID

**Prompt example:**
> "Map SD Elements project 8 to the web-app repository in ZeroPath."

### `security_compass_remove_project_mapping(mapping_id)`

Detach a project-to-repository mapping. Auto-generated rules persist; remove them separately if desired.

**Parameters:**
- `mapping_id` (required): ID of the mapping to remove

### `security_compass_sync_rules(mapping_id)`

Pull SD Elements countermeasures for a mapping, classify them (SAST-detectable / natural-language rule / unsupported), and create or update ZeroPath rules. Only one sync runs per mapping at a time.

**Parameters:**
- `mapping_id` (required): ID of the mapping to sync

**Prompt example:**
> "Sync rules for the Payment Service to web-app mapping."

### `security_compass_get_mapping_audit(mapping_id)`

Read the per-countermeasure coverage breakdown for a mapping. Available after the first successful sync.

**Parameters:**
- `mapping_id` (required): ID of the mapping to audit

**Prompt example:**
> "Show me the mapping audit for project 8."

### `security_compass_get_sync_history(limit)`

Read recent Security Compass audit-log events (sync attempts, mapping changes, integration changes).

**Parameters:**
- `limit` (optional): Maximum events to return, 1-100 (default: 20)

**Prompt example:**
> "Show recent Security Compass sync events."

---

## Development

### Running Tests

```bash
uv run pytest tests/ -v
```

### Building the Package

```bash
uv build
```

### Publishing to PyPI (Optional)

```bash
uv publish
```

---

## Contributing

We welcome contributions from the security, AI, and developer tools communities.

- Found a bug? [Open an issue](https://github.com/ZeroPathAI/zeropath-mcp-server/issues)
- Want to improve a tool or add a new one? Submit a pull request
- Have feedback or questions? Join us on [Discord](https://discord.gg/Whukqkw3Qr)

---

## License

MIT License - see [LICENSE](LICENSE) for details.
