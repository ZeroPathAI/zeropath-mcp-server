[![MseeP Badge](https://mseep.net/pr/zeropathai-zeropath-mcp-server-badge.jpg)](https://mseep.ai/app/zeropathai-zeropath-mcp-server)

# ZeroPath MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Interact with your product security findings using natural language.

This open-source MCP server allows developers to query SAST issues, secrets, patches, and more from ZeroPath directly inside AI-assisted tools like Claude Desktop, Cursor, Windsurf, and other MCP-compatible environments.

No dashboards. No manual ticket triage. Just security context where you're already working.

---

## Blog Post

Learn more about why we built this and how it fits into the evolving AI development ecosystem:

**[Chat With Your AppSec Scans: Introducing the ZeroPath MCP Server](https://zeropath.com/blog/chat-with-your-appsec-scans)**

---

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

Then set it as an environment variable:

```bash
export ZEROPATH_ORG_ID=your_org_id
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
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

To pin to a specific version, append `@v0.1.0` or `@main` to the URL.

### Using source install

If you cloned the repository locally:

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
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

### Using PyPI install (Optional)

If installed from PyPI:

```json
{
  "mcpServers": {
    "zeropath": {
      "command": "zeropath-mcp-server",
      "env": {
        "ZEROPATH_TOKEN_ID": "your_token_id",
        "ZEROPATH_TOKEN_SECRET": "your_token_secret",
        "ZEROPATH_ORG_ID": "your_org_id"
      }
    }
  }
}
```

Replace the environment variable values with your actual credentials.

---

## Available Tools

Once connected, the following tools are exposed to your AI assistant:

### Search & Issue Details

#### `search_vulnerabilities(search_query: str)`

Search for vulnerabilities using a keyword query.

**Parameters:**
- `search_query` (optional): Search term to filter vulnerabilities

**Prompt example:**
> "Show me all SSRF vulnerabilities in the user service."

---

#### `get_issue(issue_id: str)`

Get full details for a specific vulnerability issue, including patch information if available.

**Parameters:**
- `issue_id` (required): The ID of the issue to retrieve

**Prompt example:**
> "Give me the details for issue `abc123`."

---

#### `approve_patch(issue_id: str)`

Approve a patch for a specific vulnerability issue.

**Parameters:**
- `issue_id` (required): The ID of the issue whose patch should be approved

**Prompt example:**
> "Approve the patch for `xyz456`."

---

### Bug Triage

#### `mark_true_positive(issue_id: str)`

Mark a security issue as a true positive (confirmed vulnerability).

**Parameters:**
- `issue_id` (required): The ID of the issue to mark

**Prompt example:**
> "Mark issue `abc123` as a true positive."

---

#### `mark_false_positive(issue_id: str)`

Mark a security issue as a false positive (not a real vulnerability).

**Parameters:**
- `issue_id` (required): The ID of the issue to mark

**Prompt example:**
> "Mark issue `abc123` as a false positive."

---

#### `archive_issue(issue_id: str)`

Archive a security issue to remove it from active view.

**Parameters:**
- `issue_id` (required): The ID of the issue to archive

**Prompt example:**
> "Archive issue `abc123`."

---

#### `unarchive_issue(issue_id: str)`

Restore a previously archived issue to active view.

**Parameters:**
- `issue_id` (required): The ID of the issue to unarchive

**Prompt example:**
> "Unarchive issue `abc123`."

---

#### `generate_patch(issue_id: str)`

Generate an automated patch/fix for a security issue.

**Parameters:**
- `issue_id` (required): The ID of the issue to generate a patch for

**Prompt example:**
> "Generate a patch for issue `abc123`."

---

### Scan Management

#### `start_scan(repository_ids: list[str])`

Start a new security scan on one or more repositories.

**Parameters:**
- `repository_ids` (required): List of repository IDs to scan

**Prompt example:**
> "Start a scan on repository `repo_123`."

---

#### `list_scans(search_query, repository_ids, scan_type, page, page_size)`

List security scans with optional filtering and pagination.

**Parameters:**
- `search_query` (optional): Search term to filter scans
- `repository_ids` (optional): List of repository IDs to filter by
- `scan_type` (optional): Filter by scan type (`FullScan`, `PrScan`, `SCAScan`)
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Results per page (default: 10)

**Prompt example:**
> "Show me all scans for the last week."
> "List the most recent PR scans."

---

### Repository Management

#### `list_repositories(search_query: str)`

List all repositories in the organization.

**Parameters:**
- `search_query` (optional): Search term to filter repositories

**Prompt example:**
> "List all repositories."
> "Find repositories with 'api' in the name."

---

### Statistics & Analytics

#### `get_security_posture()`

Get the overall security posture metrics for the organization, including security score, vulnerability trends, and risk assessment.

**Parameters:** None

**Prompt example:**
> "What's our current security posture?"

---

#### `get_issues_by_vuln_class()`

Get issue statistics grouped by vulnerability class/type. Shows distribution of vulnerabilities by category (XSS, SQLi, etc.).

**Parameters:** None

**Prompt example:**
> "Show me a breakdown of vulnerabilities by type."

---

#### `get_summary_statistics()`

Get aggregated summary statistics across the organization, including total issues, patches, repositories, and key metrics.

**Parameters:** None

**Prompt example:**
> "Give me a summary of our security statistics."

---

### SCA (Software Composition Analysis)

#### `list_sca_vulnerabilities(search_query, repository_ids, ecosystems, transitivity, page, page_size)`

Search for SCA vulnerabilities in dependencies.

**Parameters:**
- `search_query` (optional): Search term to filter vulnerabilities
- `repository_ids` (optional): List of repository IDs to filter by
- `ecosystems` (optional): List of ecosystems to filter (`npm`, `pip`, `maven`, etc.)
- `transitivity` (optional): Filter by dependency type (`direct`, `transitive`)
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Results per page (default: 50)

**Prompt example:**
> "Show me all critical npm vulnerabilities."
> "List direct dependency vulnerabilities in the backend repo."

---

#### `get_sca_vulnerability(vulnerability_id: str)`

Get detailed information about a specific SCA vulnerability.

**Parameters:**
- `vulnerability_id` (required): The ID of the vulnerability to retrieve

**Prompt example:**
> "Get details for SCA vulnerability `vuln_456`."

---

#### `list_sca_repositories()`

List repositories with their aggregated dependency inventory information.

**Parameters:** None

**Prompt example:**
> "Which repos have the most vulnerable dependencies?"

---

## Development

### Running Tests

```bash
ZEROPATH_TOKEN_ID=your_id \
ZEROPATH_TOKEN_SECRET=your_secret \
ZEROPATH_ORG_ID=your_org \
uv run pytest tests/ -v
```

### Building the Package

```bash
uv build
```

### Publishing to PyPI (Optional)

If you want to publish to PyPI:

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
