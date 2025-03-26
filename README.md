# ZeroPath MCP Server

Interact with your product security findings using natural language.

This open-source MCP server allows developers to query SAST issues, secrets, patches, and more from ZeroPath directly inside AI-assisted tools like Claude Desktop, Cursor, Windsurf, and other MCP-compatible environments.

No dashboards. No manual ticket triage. Just security context where you're already working.

---

## Blog Post

Learn more about why we built this and how it fits into the evolving AI development ecosystem:

**📄 [Chat With Your AppSec Scans: Introducing the ZeroPath MCP Server](https://zeropath.com/blog/chat-with-your-appsec-scans)**

---

## Installation

### 1. Generate API Key

Generate an API key from your ZeroPath organization settings at [https://zeropath.com/app/settings/api](https://zeropath.com/app/settings/api)

### 2. Configure Environment Variables

Set up your environment variables with the API key:

```bash
export ZEROPATH_TOKEN_ID=your_token_id
export ZEROPATH_TOKEN_SECRET=your_token_secret
```

### 3. Retrieve Your Organization ID

Run the following command to get your organization ID:

```bash
curl -X POST https://zeropath.com/api/v1/orgs/list \
    -H "X-ZeroPath-API-Token-Id: $ZEROPATH_TOKEN_ID" \
    -H "X-ZeroPath-API-Token-Secret: $ZEROPATH_TOKEN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{}'
```

### 4. Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/)

We use `uv` for dependency management:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 5. Clone and Setup

```bash
git clone https://github.com/ZeroPathAI/zeropath-mcp-server.git
cd zeropath-mcp-server
uv sync
export ZEROPATH_ORG_ID=your_org_id
```

---

## Configuration

Add this entry to your MCP config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "zeropath-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "<absolute cloned directory path>/zeropath-mcp-server",
        "<absolute cloned directory path>/zeropath-mcp-server/main.py"
      ]
    }
  }
}
```

Replace `<absolute cloned directory path>` with the absolute path to the repo.

---

## Environment Variables

Before running the server, export the following:

```bash
export ZEROPATH_TOKEN_ID=your_token_id
export ZEROPATH_TOKEN_SECRET=your_token_secret
export ZEROPATH_ORG_ID=your_org_id
```

These can be generated from your ZeroPath dashboard.

---

## Available Tools

Once connected, the following tools are exposed to your AI assistant:

### `search_vulnerabilities(search_query: str)`

Query SAST issues by keyword.

**Prompt example:**  
> "Show me all SSRF vulnerabilities in the user service."

---

### `get_issue(issue_id: str)`

Fetch full metadata, patch suggestions, and code context for a specific issue.

**Prompt example:**  
> "Give me the details for issue `abc123`."

---

### `approve_patch(issue_id: str)`

Approve a patch (write action). Optional depending on your setup.

**Prompt example:**  
> "Approve the patch for `xyz456`."

---

## Development Mode

Use `./dev_mode.bash` to test the tools locally without a client connection.

---

## Contributing

We welcome contributions from the security, AI, and developer tools communities.

- Found a bug? [Open an issue](https://github.com/ZeroPathAI/zeropath-mcp-server/issues)
- Want to improve a tool or add a new one? Submit a pull request
- Have feedback or questions? Join us on [Discord](https://discord.gg/Whukqkw3Qr)

---
