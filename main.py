import os
import requests
from mcp.server.fastmcp import FastMCP

# Environment variables
token_id = os.getenv("ZEROPATH_TOKEN_ID")
token_secret = os.getenv("ZEROPATH_TOKEN_SECRET")
org_id = os.getenv("ZEROPATH_ORG_ID")

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

@mcp.tool()
def search_vulnerabilities(search_query=None):
    """
    Search for vulnerabilities using the Zeropath API with a simple search query.
    """
    if not token_id or not token_secret:
        return {"error": "Zeropath API credentials not found in environment variables"}
    
    # Set up headers
    headers = {
        "X-ZeroPath-API-Token-Id": token_id,
        "X-ZeroPath-API-Token-Secret": token_secret,
        "Content-Type": "application/json"
    }
    
    # Simple payload with just the search query
    payload = {}
    
    # Add search query if provided
    if search_query:
        payload["searchQuery"] = search_query
    
    # Add org_id if available
    if org_id:
        payload["organizationId"] = org_id
    
    # Make API request
    try:
        response = requests.post(
            "https://zeropath.com/api/v1/issues/search",
            headers=headers,
            json=payload
        )
        
        # Get raw JSON response
        raw_response = response.json()
        
        # Process the response to make it more LLM-friendly
        return process_vulnerability_response(raw_response)
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_issue(issue_id):
    """
    Get a specific vulnerability issue by its ID, including patch information if available.
    
    Args:
        issue_id (str): The ID of the issue to retrieve
    """
    if not token_id or not token_secret:
        return {"error": "Zeropath API credentials not found in environment variables"}
    
    if not issue_id:
        return "Error: Issue ID is required"
    
    # Set up headers
    headers = {
        "X-ZeroPath-API-Token-Id": token_id,
        "X-ZeroPath-API-Token-Secret": token_secret,
        "Content-Type": "application/json"
    }
    
    # Payload with issue ID and organization ID
    payload = {
        "issueId": issue_id,
        "organizationId": org_id
    }
    
    # Make API request
    try:
        response = requests.post(
            "https://zeropath.com/api/v1/issues/get",
            headers=headers,
            json=payload
        )
        
        # Check status code first
        if response.status_code != 200:
            return f"Error: API returned status code {response.status_code}: {response.text}"
        
        # Get raw JSON response
        try:
            raw_response = response.json()
            # Debug: Print raw response
            print("DEBUG - Raw API Response:", raw_response)
        except Exception as e:
            return f"Error: Failed to parse JSON response: {str(e)}"
        
        # Check if response is empty
        if not raw_response:
            return "Error: Empty response received from API"
            
        # Process the response
        return process_issue_response(raw_response)
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def approve_patch(issue_id):
    """
    Approve a patch for a specific vulnerability issue.
    
    Args:
        issue_id (str): The ID of the issue whose patch should be approved
    """
    if not token_id or not token_secret:
        return {"error": "Zeropath API credentials not found in environment variables"}
    
    if not issue_id:
        return "Error: Issue ID is required"
    
    # Set up headers
    headers = {
        "X-ZeroPath-API-Token-Id": token_id,
        "X-ZeroPath-API-Token-Secret": token_secret,
        "Content-Type": "application/json"
    }
    
    # Payload with issue ID and organization ID
    payload = {
        "issueId": issue_id,
        "organizationId": org_id
    }
    
    # Make API request
    try:
        response = requests.post(
            "https://zeropath.com/api/v1/issues/approve-patch",
            headers=headers,
            json=payload
        )
        
        # Check status code
        if response.status_code == 200:
            return "Patch approved successfully"
        elif response.status_code == 401:
            return "Error: Unauthorized - Invalid API credentials"
        elif response.status_code == 400:
            return "Error: Bad Request - Invalid issue ID or missing required parameters"
        else:
            return f"Error: API returned status code {response.status_code}: {response.text}"
            
    except Exception as e:
        return f"Error: {str(e)}"

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


if __name__ == "__main__":
    mcp.run(transport="stdio")