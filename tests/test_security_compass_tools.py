"""Tests for the Security Compass tools.

Stubs the tRPC client so tests run without network or credentials. Asserts
the documented dispatch — query vs mutation, procedure path, organizationId
injection — and the security posture: no tool accepts SD Elements
credentials (connecting/rotating the integration is dashboard-only).

Run with: uv run pytest tests/test_security_compass_tools.py -v
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from zeropath_mcp_server.security_compass import register_security_compass_tools
from zeropath_mcp_server.trpc_client import TrpcClient, UpstreamError

EXPECTED_TOOLS = {
    "security_compass_get_integration",
    "security_compass_test_connection",
    "security_compass_add_project_mapping",
    "security_compass_remove_project_mapping",
    "security_compass_sync_rules",
    "security_compass_get_mapping_audit",
    "security_compass_get_sync_history",
}


class _StubClient(TrpcClient):
    def __init__(self, error: UpstreamError | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self._error = error

    @property
    def organization_id(self) -> str:
        return "org_123"

    def query(self, procedure: str, payload: dict[str, Any]) -> Any:
        if self._error:
            raise self._error
        self.calls.append(("query", procedure, dict(payload)))
        return {"ok": True}

    def mutate(self, procedure: str, payload: dict[str, Any]) -> Any:
        if self._error:
            raise self._error
        self.calls.append(("mutation", procedure, dict(payload)))
        return {"ok": True}


def _make_server(client: TrpcClient) -> FastMCP:
    mcp = FastMCP("test")
    register_security_compass_tools(mcp, client)
    return mcp


def _call(mcp: FastMCP, name: str, arguments: dict[str, Any]) -> str:
    contents = asyncio.run(mcp.call_tool(name, arguments))
    assert len(contents) == 1
    return contents[0].text


def test_expected_tools_registered():
    mcp = _make_server(_StubClient())
    tools = asyncio.run(mcp.list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_no_tool_accepts_sde_credentials():
    """Connecting the integration is dashboard-only: no tool may take an SD
    Elements API token, and there is no upsert-integration tool at all."""
    mcp = _make_server(_StubClient())
    tools = asyncio.run(mcp.list_tools())
    for tool in tools:
        assert "upsert" not in tool.name
        params = json.dumps(tool.inputSchema).lower()
        assert "apitoken" not in params
        assert "api_token" not in params


def test_query_tool_dispatches_with_org_id():
    client = _StubClient()
    mcp = _make_server(client)
    _call(mcp, "security_compass_get_integration", {})
    assert client.calls == [
        ("query", "v1.securityCompass.getIntegration", {"organizationId": "org_123"}),
    ]


def test_mutation_tool_dispatches_with_args():
    client = _StubClient()
    mcp = _make_server(client)
    _call(mcp, "security_compass_sync_rules", {"mapping_id": "map_42"})
    assert client.calls == [
        (
            "mutation",
            "v1.securityCompass.syncRules",
            {"mappingId": "map_42", "organizationId": "org_123"},
        ),
    ]


def test_test_connection_sends_saved_token_probe():
    client = _StubClient()
    mcp = _make_server(client)
    _call(
        mcp,
        "security_compass_test_connection",
        {"sde_base_url": "https://acme.sdelements.com", "sde_project_id": "8"},
    )
    assert client.calls == [
        (
            "mutation",
            "v1.securityCompass.testConnection",
            {
                "sdeBaseUrl": "https://acme.sdelements.com",
                "sdeProjectId": "8",
                "organizationId": "org_123",
            },
        ),
    ]


def test_mapping_tools_dispatch():
    client = _StubClient()
    mcp = _make_server(client)
    _call(
        mcp,
        "security_compass_add_project_mapping",
        {"sde_project_id": "8", "repository_id": "repo_1"},
    )
    _call(mcp, "security_compass_remove_project_mapping", {"mapping_id": "map_42"})
    _call(mcp, "security_compass_get_mapping_audit", {"mapping_id": "map_42"})
    _call(mcp, "security_compass_get_sync_history", {"limit": 5})
    assert [c[:2] for c in client.calls] == [
        ("mutation", "v1.securityCompass.addProjectMapping"),
        ("mutation", "v1.securityCompass.removeProjectMapping"),
        ("query", "v1.securityCompass.getMappingAudit"),
        ("query", "v1.securityCompass.getSyncHistory"),
    ]


def test_result_rendered_as_json():
    mcp = _make_server(_StubClient())
    text = _call(mcp, "security_compass_get_integration", {})
    assert json.loads(text) == {"ok": True}


def test_upstream_error_returned_as_text():
    error = UpstreamError("v1.securityCompass.syncRules: CONFLICT: sync already running")
    mcp = _make_server(_StubClient(error=error))
    text = _call(mcp, "security_compass_sync_rules", {"mapping_id": "map_42"})
    assert text.startswith("Error: ")
    assert "CONFLICT" in text
