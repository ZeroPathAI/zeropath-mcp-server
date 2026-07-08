"""Security Compass (SD Elements) integration tools.

Each tool is a thin proxy to a ``v1.securityCompass.*`` tRPC procedure on
the ZeroPath frontend, called through :class:`~.trpc_client.TrpcClient`.

Deliberately absent: any tool that accepts SD Elements credentials.
Connecting the integration (supplying the SD Elements base URL and API
token) and rotating that token are dashboard-only operations — Settings →
Integrations → Security Compass — so API keys never pass through an AI
agent. The tools below operate on the connection saved there.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .trpc_client import TrpcClient, UpstreamError


def _run(client: TrpcClient, kind: str, procedure: str, payload: dict[str, Any]) -> str:
    """Call a tRPC procedure and render the result as tool output text.

    Injects the organization id from configuration — every Security Compass
    procedure requires it server-side. Upstream failures are returned as an
    ``Error:`` text payload (the convention across this server's tools)
    rather than raised, so the agent sees the upstream code/message instead
    of a generic JSON-RPC error.
    """
    payload["organizationId"] = client.organization_id
    try:
        if kind == "query":
            result = client.query(procedure, payload)
        else:
            result = client.mutate(procedure, payload)
    except UpstreamError as err:
        return f"Error: {err}"
    return json.dumps(result, default=str, indent=2)


def register_security_compass_tools(mcp: FastMCP, client: TrpcClient) -> None:
    """Register the Security Compass tools on the shared FastMCP server."""

    @mcp.tool()
    def security_compass_get_integration() -> str:
        """
        Read the Security Compass (SD Elements) integration configured for the
        organization, including all project-to-repository mappings and their
        latest sync status. Returns null if no integration is configured yet —
        the integration is created in the ZeroPath dashboard under
        Settings → Integrations → Security Compass.
        """
        return _run(client, "query", "v1.securityCompass.getIntegration", {})

    # SD Elements project ids are numeric strings ("8"). FastMCP pre-parses
    # string arguments as JSON, so "8" arrives as the int 8 — the parameter
    # accepts both and normalizes to the string the backend expects.
    @mcp.tool()
    def security_compass_test_connection(sde_base_url: str, sde_project_id: str | int) -> str:
        """
        Validate the saved SD Elements credentials against a specific project.
        Returns the countermeasure count for the project on success. Uses the
        API token saved in the dashboard — credentials are never passed
        through this tool.

        Args:
            sde_base_url: Base URL of the SD Elements tenant, e.g.
                https://acme.sdelements.com
            sde_project_id: SD Elements project id to probe.
        """
        return _run(
            client,
            "mutation",
            "v1.securityCompass.testConnection",
            {"sdeBaseUrl": sde_base_url, "sdeProjectId": str(sde_project_id)},
        )

    @mcp.tool()
    def security_compass_add_project_mapping(
        sde_project_id: str | int, repository_id: str
    ) -> str:
        """
        Link an SD Elements project to a ZeroPath repository. Adds one mapping
        per (project, repository) pair; multiple repositories can map to the
        same SD Elements project and vice versa.

        Args:
            sde_project_id: SD Elements project id.
            repository_id: ZeroPath repository id to attach.
        """
        return _run(
            client,
            "mutation",
            "v1.securityCompass.addProjectMapping",
            {"sdeProjectId": str(sde_project_id), "repositoryId": repository_id},
        )

    @mcp.tool()
    def security_compass_remove_project_mapping(mapping_id: str) -> str:
        """
        Detach a project-to-repository mapping. Auto-generated natural-language
        rules created by the mapping persist; remove them separately if desired.

        Args:
            mapping_id: Id of the mapping to remove.
        """
        return _run(
            client,
            "mutation",
            "v1.securityCompass.removeProjectMapping",
            {"mappingId": mapping_id},
        )

    @mcp.tool()
    def security_compass_sync_rules(mapping_id: str) -> str:
        """
        Trigger a rule sync for one mapping. Pulls SD Elements countermeasures,
        classifies them as SAST-detectable / natural-language rule / unsupported,
        and creates or updates ZeroPath rules accordingly. Returns sync stats.
        Errors with CONFLICT if a sync is already running for the mapping.

        Args:
            mapping_id: Id of the mapping to sync.
        """
        return _run(
            client,
            "mutation",
            "v1.securityCompass.syncRules",
            {"mappingId": mapping_id},
        )

    @mcp.tool()
    def security_compass_get_mapping_audit(mapping_id: str) -> str:
        """
        Read the per-countermeasure coverage breakdown for a mapping (covered by
        AI SAST vs natural-language rule vs unsupported). Available after the
        first successful sync.

        Args:
            mapping_id: Id of the mapping to audit.
        """
        return _run(
            client,
            "query",
            "v1.securityCompass.getMappingAudit",
            {"mappingId": mapping_id},
        )

    @mcp.tool()
    def security_compass_get_sync_history(limit: int = 20) -> str:
        """
        Read recent Security Compass audit-log events (sync attempts, mapping
        add/remove, integration changes) for the organization.

        Args:
            limit: Maximum number of events to return (1-100, default 20).
        """
        return _run(
            client,
            "query",
            "v1.securityCompass.getSyncHistory",
            {"limit": limit},
        )
