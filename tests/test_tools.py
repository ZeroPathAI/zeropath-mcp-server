"""
Tests for ZeroPath MCP Server Tools

Run with: uv run pytest tests/test_tools.py -v
"""

import os
import pytest

# Check for required environment variables before importing
REQUIRED_VARS = ["ZEROPATH_TOKEN_ID", "ZEROPATH_TOKEN_SECRET", "ZEROPATH_ORG_ID"]
missing_vars = [var for var in REQUIRED_VARS if not os.getenv(var)]

if missing_vars:
    pytest.skip(
        f"Missing required environment variables: {', '.join(missing_vars)}",
        allow_module_level=True
    )

from zeropath_mcp_server.server import (
    # Original tools
    search_vulnerabilities,
    get_issue,
    approve_patch,
    # Bug triage tools
    mark_true_positive,
    mark_false_positive,
    archive_issue,
    unarchive_issue,
    generate_patch,
    # Scan tools
    start_scan,
    list_scans,
    # Repository tools
    list_repositories,
    # Stats tools
    get_security_posture,
    get_issues_by_vuln_class,
    get_summary_statistics,
    # SCA tools
    list_sca_vulnerabilities,
    get_sca_vulnerability,
    list_sca_repositories,
)


class TestOriginalTools:
    """Tests for the original 3 tools."""

    def test_search_vulnerabilities_no_query(self):
        """Test searching vulnerabilities without a query."""
        result = search_vulnerabilities()
        assert result is not None
        assert "Error: Unauthorized" not in result or "Found" in result or "No vulnerability" in result

    def test_search_vulnerabilities_with_query(self):
        """Test searching vulnerabilities with a query."""
        result = search_vulnerabilities(search_query="XSS")
        assert result is not None
        assert isinstance(result, str)

    def test_get_issue_missing_id(self):
        """Test get_issue with missing ID."""
        result = get_issue("")
        assert "Error" in result

    def test_get_issue_invalid_id(self):
        """Test get_issue with invalid ID."""
        result = get_issue("invalid-id-12345")
        assert result is not None  # Should return error or empty

    def test_approve_patch_missing_id(self):
        """Test approve_patch with missing ID."""
        result = approve_patch("")
        assert "Error" in result


class TestBugTriageTools:
    """Tests for bug triage tools."""

    def test_mark_true_positive_missing_id(self):
        """Test mark_true_positive with missing ID."""
        result = mark_true_positive("")
        assert "Error" in result

    def test_mark_false_positive_missing_id(self):
        """Test mark_false_positive with missing ID."""
        result = mark_false_positive("")
        assert "Error" in result

    def test_archive_issue_missing_id(self):
        """Test archive_issue with missing ID."""
        result = archive_issue("")
        assert "Error" in result

    def test_unarchive_issue_missing_id(self):
        """Test unarchive_issue with missing ID."""
        result = unarchive_issue("")
        assert "Error" in result

    def test_generate_patch_missing_id(self):
        """Test generate_patch with missing ID."""
        result = generate_patch("")
        assert "Error" in result


class TestScanTools:
    """Tests for scan management tools."""

    def test_start_scan_missing_repos(self):
        """Test start_scan with missing repository IDs."""
        result = start_scan([])
        assert "Error" in result

    def test_list_scans_default(self):
        """Test list_scans with default parameters."""
        result = list_scans()
        assert result is not None
        assert isinstance(result, str)
        # Should return either scans or "No scans found"
        assert "scan" in result.lower() or "error" in result.lower()

    def test_list_scans_with_pagination(self):
        """Test list_scans with pagination."""
        result = list_scans(page=1, page_size=5)
        assert result is not None

    def test_list_scans_invalid_type(self):
        """Test list_scans with invalid scan type."""
        result = list_scans(scan_type="InvalidType")
        assert "Error" in result


class TestRepositoryTools:
    """Tests for repository tools."""

    def test_list_repositories_default(self):
        """Test list_repositories with default parameters."""
        result = list_repositories()
        assert result is not None
        assert isinstance(result, str)
        # Should return repositories or "No repositories found"
        assert "repository" in result.lower() or "repo" in result.lower() or "error" in result.lower()

    def test_list_repositories_with_search(self):
        """Test list_repositories with search query."""
        result = list_repositories(search_query="test")
        assert result is not None


class TestStatsTools:
    """Tests for stats and analytics tools."""

    def test_get_security_posture(self):
        """Test get_security_posture."""
        result = get_security_posture()
        assert result is not None
        assert isinstance(result, str)

    def test_get_issues_by_vuln_class(self):
        """Test get_issues_by_vuln_class."""
        result = get_issues_by_vuln_class()
        assert result is not None
        assert isinstance(result, str)

    def test_get_summary_statistics(self):
        """Test get_summary_statistics."""
        result = get_summary_statistics()
        assert result is not None
        assert isinstance(result, str)


class TestSCATools:
    """Tests for SCA (Software Composition Analysis) tools."""

    def test_list_sca_vulnerabilities_default(self):
        """Test list_sca_vulnerabilities with default parameters."""
        result = list_sca_vulnerabilities()
        assert result is not None
        assert isinstance(result, str)

    def test_list_sca_vulnerabilities_with_pagination(self):
        """Test list_sca_vulnerabilities with pagination."""
        result = list_sca_vulnerabilities(page=1, page_size=10)
        assert result is not None

    def test_list_sca_vulnerabilities_invalid_transitivity(self):
        """Test list_sca_vulnerabilities with invalid transitivity."""
        result = list_sca_vulnerabilities(transitivity="invalid")
        assert "Error" in result

    def test_get_sca_vulnerability_missing_id(self):
        """Test get_sca_vulnerability with missing ID."""
        result = get_sca_vulnerability("")
        assert "Error" in result

    def test_list_sca_repositories(self):
        """Test list_sca_repositories."""
        result = list_sca_repositories()
        assert result is not None
        assert isinstance(result, str)


class TestIntegration:
    """Integration tests that test tool workflows."""

    def test_search_and_get_issue_workflow(self):
        """Test searching for issues and then getting details."""
        # First search for vulnerabilities
        search_result = search_vulnerabilities()
        assert search_result is not None

        # If we found issues, try to get the first one
        if "ID:" in search_result and "Error" not in search_result:
            # Extract first issue ID (basic parsing)
            lines = search_result.split("\n")
            for line in lines:
                if line.startswith("ID:"):
                    issue_id = line.replace("ID:", "").strip()
                    if issue_id and issue_id != "N/A":
                        # Get issue details
                        issue_result = get_issue(issue_id)
                        assert issue_result is not None
                        break

    def test_list_repos_and_scan_workflow(self):
        """Test listing repos and checking scans."""
        # List repositories
        repos_result = list_repositories()
        assert repos_result is not None

        # List recent scans
        scans_result = list_scans()
        assert scans_result is not None


# Quick smoke test that can be run independently
def test_smoke():
    """Quick smoke test to verify basic connectivity."""
    # Just test that we can call a simple read-only endpoint
    result = list_repositories()
    assert result is not None
    print(f"\nSmoke test result:\n{result[:500]}...")


if __name__ == "__main__":
    # Run smoke test directly
    print("Running smoke test...")
    test_smoke()
    print("\nSmoke test passed!")
    print("\nTo run all tests: uv run pytest tests/test_tools.py -v")
