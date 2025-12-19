"""
ZeroPath MCP Server

Provides tools for interacting with ZeroPath security findings via the MCP protocol.
"""

import os
import requests
from mcp.server.fastmcp import FastMCP

# Environment variables
token_id = os.getenv("ZEROPATH_TOKEN_ID")
token_secret = os.getenv("ZEROPATH_TOKEN_SECRET")
org_id = os.getenv("ZEROPATH_ORG_ID")

# API base URL
API_BASE_URL = "https://zeropath.com/api/v1"


def make_api_request(endpoint, payload=None, include_org=True):
    """Make authenticated API request to ZeroPath."""
    if not token_id or not token_secret:
        return None, "Error: Zeropath API credentials not found in environment variables"

    headers = {
        "X-ZeroPath-API-Token-Id": token_id,
        "X-ZeroPath-API-Token-Secret": token_secret,
        "Content-Type": "application/json"
    }

    if payload is None:
        payload = {}

    if include_org and org_id:
        payload["organizationId"] = org_id

    try:
        response = requests.post(
            f"{API_BASE_URL}/{endpoint}",
            headers=headers,
            json=payload
        )
        return response, None
    except Exception as e:
        return None, f"Error: {str(e)}"


def handle_response(response, error, success_processor=None):
    """Handle API response with standard error checking."""
    if error:
        return error

    if response.status_code == 200:
        if success_processor:
            return success_processor(response.json())
        return response.json()
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"

# Check if required environment variables are set
if not token_id or not token_secret or not org_id:
    missing_vars = []
    if not token_id:
        missing_vars.append("ZEROPATH_TOKEN_ID")
    if not token_secret:
        missing_vars.append("ZEROPATH_TOKEN_SECRET")
    if not org_id:
        missing_vars.append("ZEROPATH_ORG_ID")
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

mcp = FastMCP("Zeropath")

# =============================================================================
# NOTE: This MCP server requires an admin/organization API key from ZeroPath.
# Regular user API keys will not have access to most of these endpoints.
# Generate an org API key at: https://zeropath.com/settings/api-keys
# =============================================================================

@mcp.tool()
def search_vulnerabilities(search_query=None):
    """
    Search for vulnerabilities using the Zeropath API with a simple search query.
    """
    payload = {}
    if search_query:
        payload["searchQuery"] = search_query

    response, error = make_api_request("issues/search", payload)

    if error:
        return error

    if response.status_code == 200:
        return process_vulnerability_response(response.json())
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def get_issue(issue_id):
    """
    Get a specific vulnerability issue by its ID, including patch information if available.

    Args:
        issue_id (str): The ID of the issue to retrieve
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request("issues/get", {"issueId": issue_id})

    if error:
        return error

    if response.status_code == 200:
        raw_response = response.json()
        if not raw_response:
            return "Error: Empty response received from API"
        return process_issue_response(raw_response)
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def approve_patch(issue_id):
    """
    Approve a patch for a specific vulnerability issue.

    Args:
        issue_id (str): The ID of the issue whose patch should be approved
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request("issues/approve-patch", {"issueId": issue_id})

    if error:
        return error

    if response.status_code == 200:
        return "Patch approved successfully"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


# =============================================================================
# BUG TRIAGE TOOLS
# =============================================================================

@mcp.tool()
def mark_true_positive(issue_id: str) -> str:
    """
    Mark a security issue as a true positive (confirmed vulnerability).

    Args:
        issue_id: The ID of the issue to mark as true positive
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request(
        "issues/mark-true-positive",
        {"issueId": issue_id}
    )

    if error:
        return error

    if response.status_code == 200:
        return f"Issue {issue_id} marked as true positive successfully"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def mark_false_positive(issue_id: str) -> str:
    """
    Mark a security issue as a false positive (not a real vulnerability).

    Args:
        issue_id: The ID of the issue to mark as false positive
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request(
        "issues/mark-false-positive",
        {"issueId": issue_id}
    )

    if error:
        return error

    if response.status_code == 200:
        return f"Issue {issue_id} marked as false positive successfully"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def archive_issue(issue_id: str) -> str:
    """
    Archive a security issue to remove it from active view.

    Args:
        issue_id: The ID of the issue to archive
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request(
        "issues/archive",
        {"issueId": issue_id}
    )

    if error:
        return error

    if response.status_code == 200:
        return f"Issue {issue_id} archived successfully"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def unarchive_issue(issue_id: str) -> str:
    """
    Unarchive a previously archived security issue to restore it to active view.

    Args:
        issue_id: The ID of the issue to unarchive
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request(
        "issues/unarchive",
        {"issueId": issue_id}
    )

    if error:
        return error

    if response.status_code == 200:
        return f"Issue {issue_id} unarchived successfully"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def generate_patch(issue_id: str) -> str:
    """
    Generate an automated patch/fix for a security issue.

    Args:
        issue_id: The ID of the issue to generate a patch for
    """
    if not issue_id:
        return "Error: Issue ID is required"

    response, error = make_api_request(
        "issues/generate-patch",
        {"issueId": issue_id}
    )

    if error:
        return error

    if response.status_code == 200:
        result = response.json()
        if result.get("patch"):
            return f"Patch generated successfully for issue {issue_id}. Use get_issue({issue_id}) to view the patch details."
        return f"Patch generation initiated for issue {issue_id}. This may take a moment."
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


# =============================================================================
# SCAN MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def start_scan(repository_ids: list[str]) -> str:
    """
    Start a new security scan on one or more repositories.

    Args:
        repository_ids: List of repository IDs to scan
    """
    if not repository_ids:
        return "Error: At least one repository ID is required"

    response, error = make_api_request(
        "scans/start",
        {"repositoryIds": repository_ids}
    )

    if error:
        return error

    if response.status_code == 200:
        result = response.json()
        scan_id = result.get("scanId", result.get("id", "unknown"))
        return f"Scan started successfully. Scan ID: {scan_id}"
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def list_scans(
    search_query: str = None,
    repository_ids: list[str] = None,
    scan_type: str = None,
    page: int = 1,
    page_size: int = 10
) -> str:
    """
    List security scans with optional filtering and pagination.

    Args:
        search_query: Optional search term to filter scans
        repository_ids: Optional list of repository IDs to filter by
        scan_type: Optional scan type filter (FullScan, PrScan, SCAScan)
        page: Page number (default: 1)
        page_size: Number of results per page (default: 10)
    """
    payload = {
        "page": page,
        "pageSize": page_size
    }

    if search_query:
        payload["searchQuery"] = search_query
    if repository_ids:
        payload["repositoryIds"] = repository_ids
    if scan_type:
        valid_types = ["FullScan", "PrScan", "SCAScan"]
        if scan_type not in valid_types:
            return f"Error: Invalid scan type. Must be one of: {', '.join(valid_types)}"
        payload["scanType"] = scan_type

    response, error = make_api_request("scans/list", payload)

    if error:
        return error

    if response.status_code == 200:
        return process_scans_response(response.json())
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


def process_scans_response(raw_response):
    """Process scans list response into readable format."""
    if "error" in raw_response:
        return f"Error: {raw_response['error']}"

    scans = raw_response.get("scans", raw_response.get("items", []))
    if not scans:
        return "No scans found."

    total_count = raw_response.get("totalCount", len(scans))
    result = f"Found {total_count} scan(s).\n\n"

    for i, scan in enumerate(scans, 1):
        result += f"Scan {i}:\n"
        result += f"  ID: {scan.get('id', 'N/A')}\n"
        result += f"  Status: {scan.get('status', 'N/A')}\n"
        result += f"  Type: {scan.get('scanType', 'N/A')}\n"
        result += f"  Repository: {scan.get('repositoryName', scan.get('repositoryId', 'N/A'))}\n"
        result += f"  Branch: {scan.get('branch', 'N/A')}\n"
        result += f"  Created: {scan.get('createdAt', 'N/A')}\n"
        result += f"  Updated: {scan.get('updatedAt', 'N/A')}\n"

        # Issue counts if available
        if scan.get('openIssues') is not None:
            result += f"  Open Issues: {scan.get('openIssues', 0)}\n"
        if scan.get('patchedIssues') is not None:
            result += f"  Patched Issues: {scan.get('patchedIssues', 0)}\n"
        if scan.get('falsePositiveIssues') is not None:
            result += f"  False Positives: {scan.get('falsePositiveIssues', 0)}\n"

        result += "\n"

    # Pagination info
    if "page" in raw_response or "currentPage" in raw_response:
        result += f"Page: {raw_response.get('page', raw_response.get('currentPage', 1))}\n"
        result += f"Page Size: {raw_response.get('pageSize', len(scans))}\n"

    return result


# =============================================================================
# REPOSITORY MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def list_repositories(search_query: str = None) -> str:
    """
    List all repositories in the organization.

    Args:
        search_query: Optional search term to filter repositories
    """
    payload = {}
    if search_query:
        payload["searchQuery"] = search_query

    response, error = make_api_request("repositories/list", payload)

    if error:
        return error

    if response.status_code == 200:
        return process_repositories_response(response.json())
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


def process_repositories_response(raw_response):
    """Process repositories list response into readable format."""
    # Handle list response directly
    if isinstance(raw_response, list):
        repos = raw_response
    else:
        if "error" in raw_response:
            return f"Error: {raw_response['error']}"
        repos = raw_response.get("repositories", raw_response.get("items", []))

    if not repos:
        return "No repositories found."

    total_count = len(repos)
    result = f"Found {total_count} repository(ies).\n\n"

    for i, repo in enumerate(repos, 1):
        result += f"Repository {i}:\n"
        result += f"  ID: {repo.get('id', 'N/A')}\n"
        result += f"  Name: {repo.get('name', 'N/A')}\n"
        result += f"  Full Name: {repo.get('fullName', repo.get('full_name', 'N/A'))}\n"
        result += f"  Provider: {repo.get('provider', 'N/A')}\n"
        result += f"  Default Branch: {repo.get('defaultBranch', repo.get('scanBranch', 'N/A'))}\n"
        result += f"  PR Scanning: {repo.get('prScanningEnabled', 'N/A')}\n"
        result += f"  Last Scanned: {repo.get('lastScannedAt', 'N/A')}\n"
        result += "\n"

    return result


# =============================================================================
# STATS & ANALYTICS TOOLS
# =============================================================================

@mcp.tool()
def get_security_posture() -> str:
    """
    Get the overall security posture metrics for the organization.
    Returns security score, vulnerability trends, and risk assessment.
    """
    response, error = make_api_request("stats/securityPosture")

    if error:
        return error

    if response.status_code == 200:
        return process_stats_response(response.json(), "Security Posture")
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def get_issues_by_vuln_class() -> str:
    """
    Get issue statistics grouped by vulnerability class/type.
    Shows distribution of vulnerabilities by category (XSS, SQLi, etc.).
    """
    response, error = make_api_request("stats/issuesByVulnClass")

    if error:
        return error

    if response.status_code == 200:
        return process_stats_response(response.json(), "Issues by Vulnerability Class")
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def get_summary_statistics() -> str:
    """
    Get aggregated summary statistics across the organization.
    Includes total issues, patches, repositories, and key metrics.
    """
    response, error = make_api_request("stats/summary")

    if error:
        return error

    if response.status_code == 200:
        return process_stats_response(response.json(), "Summary Statistics")
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


def process_stats_response(raw_response, title):
    """Process stats response into readable format."""
    # Handle list response directly
    if isinstance(raw_response, list):
        result = f"=== {title} ===\n\n"
        for i, item in enumerate(raw_response, 1):
            if isinstance(item, dict):
                result += f"Item {i}:\n"
                for k, v in item.items():
                    formatted_key = ''.join(' ' + c if c.isupper() else c for c in str(k)).strip().title()
                    result += f"  {formatted_key}: {v}\n"
                result += "\n"
            else:
                result += f"  - {item}\n"
        return result

    if isinstance(raw_response, dict) and "error" in raw_response:
        return f"Error: {raw_response['error']}"

    result = f"=== {title} ===\n\n"

    def format_value(key, value, indent=0):
        """Format a key-value pair with proper indentation."""
        prefix = "  " * indent
        if isinstance(value, dict):
            output = f"{prefix}{key}:\n"
            for k, v in value.items():
                output += format_value(k, v, indent + 1)
            return output
        elif isinstance(value, list):
            output = f"{prefix}{key}:\n"
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    output += f"{prefix}  Item {i + 1}:\n"
                    for k, v in item.items():
                        output += format_value(k, v, indent + 2)
                else:
                    output += f"{prefix}  - {item}\n"
            return output
        else:
            # Format the key nicely (camelCase to Title Case)
            formatted_key = ''.join(' ' + c if c.isupper() else c for c in key).strip().title()
            return f"{prefix}{formatted_key}: {value}\n"

    for key, value in raw_response.items():
        result += format_value(key, value)

    return result


# =============================================================================
# SCA (SOFTWARE COMPOSITION ANALYSIS) TOOLS
# =============================================================================

@mcp.tool()
def list_sca_vulnerabilities(
    search_query: str = None,
    repository_ids: list[str] = None,
    ecosystems: list[str] = None,
    transitivity: str = None,
    page: int = 1,
    page_size: int = 50
) -> str:
    """
    Search for SCA (Software Composition Analysis) vulnerabilities in dependencies.

    Args:
        search_query: Optional search term to filter vulnerabilities
        repository_ids: Optional list of repository IDs to filter by
        ecosystems: Optional list of ecosystems to filter (npm, pip, maven, etc.)
        transitivity: Optional filter by dependency type (direct, transitive)
        page: Page number (default: 1)
        page_size: Number of results per page (default: 50)
    """
    payload = {
        "page": page,
        "pageSize": page_size
    }

    if search_query:
        payload["searchQuery"] = search_query
    if repository_ids:
        payload["repositoryIds"] = repository_ids
    if ecosystems:
        payload["ecosystems"] = ecosystems
    if transitivity:
        if transitivity not in ["direct", "transitive"]:
            return "Error: transitivity must be 'direct' or 'transitive'"
        payload["transitivity"] = transitivity

    response, error = make_api_request("sca/vulnerabilities/search", payload)

    if error:
        return error

    if response.status_code == 200:
        return process_sca_vulnerabilities_response(response.json())
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def get_sca_vulnerability(vulnerability_id: str) -> str:
    """
    Get detailed information about a specific SCA vulnerability.

    Args:
        vulnerability_id: The ID of the vulnerability to retrieve
    """
    if not vulnerability_id:
        return "Error: Vulnerability ID is required"

    response, error = make_api_request(
        "sca/vulnerabilities/get",
        {"vulnerabilityId": vulnerability_id}
    )

    if error:
        return error

    if response.status_code == 200:
        vuln = response.json()

        output = "SCA Vulnerability Details:\n\n"
        output += f"ID: {vuln.get('id', 'N/A')}\n"
        output += f"Package: {vuln.get('packageName', 'N/A')}\n"
        output += f"Version: {vuln.get('version', 'N/A')}\n"
        output += f"Ecosystem: {vuln.get('ecosystem', 'N/A')}\n"
        output += f"Severity: {vuln.get('severity', 'N/A')}\n"
        output += f"CVSS Score: {vuln.get('cvssScore', vuln.get('severityScore', 'N/A'))}\n"

        # Advisory info
        if vuln.get('aliases'):
            output += f"Aliases: {', '.join(vuln['aliases'])}\n"
        if vuln.get('cve'):
            output += f"CVE: {vuln['cve']}\n"

        output += f"\nSummary: {vuln.get('summary', 'N/A')}\n"
        output += f"\nDescription: {vuln.get('description', 'N/A')}\n"

        # Fix info
        if vuln.get('fixedVersion'):
            output += f"\nFixed in Version: {vuln['fixedVersion']}\n"
        if vuln.get('references'):
            output += "\nReferences:\n"
            for ref in vuln['references'][:5]:  # Limit to 5 references
                output += f"  - {ref}\n"

        return output
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


@mcp.tool()
def list_sca_repositories() -> str:
    """
    List repositories with their aggregated dependency inventory information.
    Shows which repositories have been analyzed for dependencies.
    """
    response, error = make_api_request("sca/repositories/search")

    if error:
        return error

    if response.status_code == 200:
        result = response.json()
        repos = result.get("repositories", result if isinstance(result, list) else [])

        if not repos:
            return "No repositories with SCA data found."

        output = f"Found {len(repos)} repository(ies) with SCA data:\n\n"
        for i, repo in enumerate(repos, 1):
            output += f"Repository {i}:\n"
            output += f"  ID: {repo.get('id', repo.get('repositoryId', 'N/A'))}\n"
            output += f"  Name: {repo.get('name', repo.get('repositoryName', 'N/A'))}\n"
            output += f"  Total Dependencies: {repo.get('totalDependencies', repo.get('dependencyCount', 'N/A'))}\n"
            output += f"  Vulnerable Packages: {repo.get('vulnerablePackages', 'N/A')}\n"
            output += f"  Critical: {repo.get('criticalCount', 'N/A')}\n"
            output += f"  High: {repo.get('highCount', 'N/A')}\n"
            output += f"  Medium: {repo.get('mediumCount', 'N/A')}\n"
            output += f"  Low: {repo.get('lowCount', 'N/A')}\n"
            output += "\n"
        return output
    elif response.status_code == 401:
        return "Error: Unauthorized - check API credentials"
    elif response.status_code == 400:
        return f"Error: Bad request - {response.text}"
    else:
        return f"Error: API returned status {response.status_code}: {response.text}"


def process_sca_vulnerabilities_response(raw_response):
    """Process SCA vulnerabilities search response into readable format."""
    if "error" in raw_response:
        return f"Error: {raw_response['error']}"

    vulns = raw_response.get("vulnerabilities", raw_response.get("items", []))
    if not vulns:
        return "No SCA vulnerabilities found."

    total_count = raw_response.get("totalCount", len(vulns))
    result = f"Found {total_count} SCA vulnerability(ies).\n\n"

    for i, vuln in enumerate(vulns, 1):
        result += f"Vulnerability {i}:\n"
        result += f"  ID: {vuln.get('id', 'N/A')}\n"

        # Package info
        pkg = vuln.get('package', {})
        if pkg:
            result += f"  Package: {pkg.get('name', 'N/A')} @ {pkg.get('version', 'N/A')}\n"
            result += f"  Ecosystem: {pkg.get('ecosystem', 'N/A')}\n"
            result += f"  Manifest: {pkg.get('manifestPath', 'N/A')}\n"
        else:
            result += f"  Package: {vuln.get('packageName', 'N/A')}\n"

        # Metadata
        meta = vuln.get('metadata', {})
        if meta:
            result += f"  Severity: {meta.get('severity', 'N/A')}\n"
            result += f"  Score: {meta.get('severityScore', 'N/A')}\n"
            result += f"  Summary: {meta.get('summary', 'N/A')}\n"
            if meta.get('aliases'):
                result += f"  Aliases: {', '.join(meta['aliases'][:3])}\n"
        else:
            result += f"  Severity: {vuln.get('severity', 'N/A')}\n"

        result += f"  Repository: {vuln.get('repositoryId', 'N/A')}\n"
        result += f"  Branch: {vuln.get('branch', 'N/A')}\n"
        result += "\n"

    # Pagination info
    if "page" in raw_response:
        result += f"Page: {raw_response.get('page', 1)} | "
        result += f"Page Size: {raw_response.get('pageSize', len(vulns))} | "
        result += f"Total: {total_count}\n"

    return result


def process_issue_response(issue):
    """
    Process a single issue response into a readable format, focusing on the issue details and patch.
    """
    if not issue:
        return "Error: Empty issue data"

    if "error" in issue and issue["error"]:
        return f"Error: {issue['error']}"

    # Check if we have a valid issue (must have an id at minimum)
    if not issue.get('id'):
        return "Error: Invalid issue data received - missing ID"

    # Get patch information if available
    patch = issue.get("patch") or issue.get("vulnerabilityPatch")

    result = "Issue Details:\n"

    result += f"ID: {issue.get('id', 'N/A')}\n"
    result += f"Status: {issue.get('status', 'N/A')}\n"
    result += f"Title: {issue.get('generatedTitle', 'N/A')}\n"
    result += f"Description: {issue.get('generatedDescription', 'N/A')}\n"
    result += f"Language: {issue.get('language', 'N/A')}\n"
    result += f"Vulnerability Class: {issue.get('vulnClass', 'N/A')}\n"

    if issue.get("cwes"):
        result += f"CWEs: {', '.join(issue.get('cwes', []))}\n"

    result += f"Severity: {issue.get('severity', 'N/A')}\n"
    result += f"Affected File: {issue.get('affectedFile', 'N/A')}\n"

    if issue.get("startLine") and issue.get("endLine"):
        result += f"Location: Lines {issue.get('startLine')} to {issue.get('endLine')}\n"

    result += f"Validation Status: {issue.get('validated', 'N/A')}\n"
    result += f"Unpatchable: {issue.get('unpatchable', False)}\n"
    result += f"Triage Phase: {issue.get('triagePhase', 'N/A')}\n"

    # Add code segment if available
    if issue.get("sastCodeSegment"):
        result += "\nVulnerable Code Segment:\n"
        result += f"```\n{issue.get('sastCodeSegment')}\n```\n"

    # Add patch information if available
    if patch and not issue.get("unpatchable", False):
        result += "\n========== PATCH INFORMATION ==========\n"
        result += f"PR Link: {patch.get('prLink', 'N/A')}\n"
        result += f"PR Title: {patch.get('prTitle', 'N/A')}\n"
        result += f"PR Description: {patch.get('prDescription', 'N/A')}\n"
        result += f"PR Status: {patch.get('pullRequestStatus', 'N/A')}\n"
        result += f"Validation Status: {patch.get('validated', 'N/A')}\n"
        result += f"Created At: {patch.get('createdAt', 'N/A')}\n"
        result += f"Updated At: {patch.get('updatedAt', 'N/A')}\n"

        # Add git diff if available
        if patch.get("gitDiff"):
            result += "\n========== PATCH ID & GIT DIFF ==========\n"
            result += f"PATCH ID: {patch.get('id', 'N/A')}\n"
            result += "========================================\n"
            result += "Git Diff:\n"
            result += f"```diff\n{patch.get('gitDiff')}\n```\n"

    return result

def process_vulnerability_response(raw_response):
    """
    Process the raw API response into a more readable format for LLMs.
    Extracts and organizes the most relevant information in plain text format.
    """
    if "error" in raw_response:
        return f"Error: {raw_response['error']}"

    if "issues" not in raw_response:
        return "No vulnerability issues found in the response."

    # Count totals and categorize issues
    total_issues = len(raw_response["issues"])
    patchable_count = sum(1 for issue in raw_response["issues"] if not issue.get("unpatchable", False))
    unpatchable_count = sum(1 for issue in raw_response["issues"] if issue.get("unpatchable", True))

    # Build a formatted text response
    result = f"Found {total_issues} vulnerability issues. {patchable_count} are patchable, {unpatchable_count} are unpatchable.\n\n"

    # Process each issue
    for i, issue in enumerate(raw_response["issues"], 1):
        result += f"Issue {i}:\n"
        result += f"ID: {issue.get('id')}\n"
        result += f"Status: {issue.get('status', 'unknown')}\n"

        # Include all fields that exist
        if issue.get("type"):
            result += f"Type: {issue.get('type')}\n"

        if issue.get("patchable") is not None:
            patchable = not issue.get("unpatchable", False)
            result += f"Patchable: {patchable}\n"

        if issue.get("language"):
            result += f"Language: {issue['language']}\n"

        if issue.get("score") is not None:
            result += f"Score: {issue['score']}\n"

        if issue.get("severity") is not None:
            result += f"Severity: {issue['severity']}\n"

        if issue.get("generatedTitle"):
            result += f"Title: {issue['generatedTitle']}\n"

        if issue.get("generatedDescription"):
            result += f"Description: {issue['generatedDescription']}\n"

        if issue.get("affectedFile"):
            result += f"Affected File: {issue['affectedFile']}\n"

        if issue.get("cwes"):
            result += f"CWEs: {', '.join(issue['cwes'])}\n"

        if issue.get("validated"):
            result += f"Validation Status: {issue['validated']}\n"

        if issue.get("triagePhase"):
            result += f"Triage Phase: {issue['triagePhase']}\n"

        # Add patch information if available
        if issue.get("vulnerabilityPatch") and not issue.get("unpatchable", False):
            patch = issue["vulnerabilityPatch"]
            result += "\n--- PATCH INFORMATION ---\n"
            result += f"PATCH ID: {patch.get('id', 'N/A')}\n"
            result += "------------------------\n"
            result += "Has Patch: Yes\n"

            if patch.get("pullRequestStatus"):
                result += f"Patch Status: {patch['pullRequestStatus']}\n"

        # Add extra space between issues
        result += "\n"

    # Include pagination info if available
    if "currentPage" in raw_response or "pageSize" in raw_response:
        result += "Pagination Info:\n"
        result += f"Current Page: {raw_response.get('currentPage', 1)}\n"
        result += f"Page Size: {raw_response.get('pageSize', total_issues)}\n"

    return result
