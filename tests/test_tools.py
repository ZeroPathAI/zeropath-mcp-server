"""
Tests for ZeroPath MCP Server (manifest-driven).

Run with: uv run pytest tests/test_tools.py -v
"""

import os

# Ensure required environment variables exist before importing the server module.
os.environ.setdefault("ZEROPATH_TOKEN_ID", "test-token-id")
os.environ.setdefault("ZEROPATH_TOKEN_SECRET", "test-token-secret")
os.environ.setdefault("ZEROPATH_ORG_ID", "org_test")
os.environ.setdefault("ZEROPATH_BASE_URL", "https://example.com")

import json

import pytest

import zeropath_mcp_server.trpc_client as trpc_client
from zeropath_mcp_server import server


SAMPLE_MANIFEST = {
    "version": 1,
    "generatedAt": "2026-01-01T00:00:00.000Z",
    "tools": [
        {
            "name": "issues.list",
            "trpcProcedure": "v2.issues.list",
            "procedureType": "query",
            "description": "List security issues",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "organizationId": {"type": "string"},
                    "page": {"type": "integer"},
                },
            },
            "orgIdBehavior": "inject-if-missing",
        },
        {
            "name": "stats.assets",
            "trpcProcedure": "v2.stats.assets",
            "procedureType": "query",
            "description": "Get asset stats",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "organizationId": {"type": "string"},
                },
                "required": ["organizationId"],
            },
            "orgIdBehavior": "required",
        },
        {
            "name": "rules.get",
            "trpcProcedure": "v2.rules.get",
            "procedureType": "query",
            "description": "Get a rule",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ruleId": {"type": "string"},
                },
                "required": ["ruleId"],
            },
            "orgIdBehavior": "none",
        },
    ],
}


class TestBuildTools:
    def test_parses_tools_from_manifest(self):
        tools, metadata = server._build_tools(SAMPLE_MANIFEST)

        assert len(tools) == 3
        assert tools[0].name == "issues.list"
        assert tools[0].description == "List security issues"
        assert tools[0].inputSchema["type"] == "object"

    def test_builds_metadata_lookup(self):
        _, metadata = server._build_tools(SAMPLE_MANIFEST)

        assert metadata["issues.list"]["trpcProcedure"] == "v2.issues.list"
        assert metadata["issues.list"]["orgIdBehavior"] == "inject-if-missing"
        assert metadata["stats.assets"]["orgIdBehavior"] == "required"
        assert metadata["rules.get"]["orgIdBehavior"] == "none"

    def test_empty_manifest(self):
        tools, metadata = server._build_tools({"version": 1, "tools": []})
        assert tools == []
        assert metadata == {}


class TestApplyOrgId:
    def test_inject_if_missing_adds_org_id(self):
        args = {"page": 1}
        error = server._apply_org_id(args, "inject-if-missing", organization_id="org_test")
        assert error is None
        assert args["organizationId"] == "org_test"

    def test_inject_if_missing_preserves_existing(self):
        args = {"organizationId": "org_custom", "page": 1}
        error = server._apply_org_id(args, "inject-if-missing", organization_id="org_test")
        assert error is None
        assert args["organizationId"] == "org_custom"

    def test_required_injects_from_config(self):
        args = {}
        error = server._apply_org_id(args, "required", organization_id="org_test")
        assert error is None
        assert args["organizationId"] == "org_test"

    def test_required_fails_when_config_empty(self):
        args = {}
        error = server._apply_org_id(args, "required", organization_id="")
        assert error == "organizationId is required"

    def test_none_skips_injection(self):
        args = {"page": 1}
        error = server._apply_org_id(args, "none", organization_id="org_test")
        assert error is None
        assert "organizationId" not in args


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


class TestTrpcClient:
    def test_trpc_request_builds_url_and_headers(self, monkeypatch):
        captured = {}

        def fake_get(url, headers=None, params=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["params"] = params
            return DummyResponse({"result": {"data": {"ok": True}}})

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "v2.issues.list",
            {"organizationId": "org_test"},
            procedure_type="query",
        )

        assert result == {"ok": True}
        assert captured["url"] == "https://example.com/trpc/v2.issues.list"
        assert captured["headers"]["X-ZeroPath-API-Token-Id"] == "test-token-id"
        assert captured["headers"]["X-ZeroPath-API-Token-Secret"] == "test-token-secret"
        assert captured["headers"]["X-ZeroPath-Client"] == "zeropath-mcp-server"
        assert json.loads(captured["params"]["input"])["organizationId"] == "org_test"

    def test_trpc_error_passthrough(self, monkeypatch):
        def fake_get(url, headers=None, params=None, timeout=None):
            return DummyResponse({"error": {"message": "Unauthorized", "code": "UNAUTHORIZED"}}, status_code=401)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "v2.repositories.list",
            {},
            procedure_type="query",
        )
        assert result == {"error": {"message": "Unauthorized", "code": "UNAUTHORIZED"}}

    def test_trpc_mutation_sends_raw_json_body(self, monkeypatch):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return DummyResponse({"result": {"data": {"ok": True}}})

        monkeypatch.setattr(trpc_client.requests, "post", fake_post)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "v2.issues.archive",
            {"issueIds": ["issue_1"], "reason": "test"},
            procedure_type="mutation",
        )

        assert result == {"ok": True}
        assert captured["url"] == "https://example.com/trpc/v2.issues.archive"
        assert captured["json"] == {"issueIds": ["issue_1"], "reason": "test"}


class TestFetchManifest:
    def test_successful_fetch(self, monkeypatch):
        def fake_get(url, timeout=None):
            return DummyResponse(SAMPLE_MANIFEST)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.fetch_manifest()
        assert result["version"] == 1
        assert len(result["tools"]) == 3

    def test_rejects_bad_version(self, monkeypatch):
        def fake_get(url, timeout=None):
            return DummyResponse({"version": 99, "tools": []})

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        with pytest.raises(RuntimeError, match="Unsupported manifest version"):
            client.fetch_manifest()

    def test_rejects_http_error(self, monkeypatch):
        def fake_get(url, timeout=None):
            return DummyResponse("Not Found", status_code=404)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        with pytest.raises(RuntimeError, match="HTTP 404"):
            client.fetch_manifest()


class TestCallTool:
    """Test the call_tool handler via create_server()."""

    @pytest.fixture
    def mock_server(self, monkeypatch):
        """Create a server with a mocked manifest fetch."""
        def fake_get(url, timeout=None):
            return DummyResponse(SAMPLE_MANIFEST)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)
        return server.create_server()

    def test_unknown_tool_returns_error(self, mock_server):
        import asyncio
        import mcp.types as types

        handler = mock_server.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="no.such.tool", arguments=None),
        )
        result = asyncio.run(handler(req))

        assert result.root.isError is True
        assert len(result.root.content) == 1
        payload = json.loads(result.root.content[0].text)
        assert payload["error"]["code"] == "NOT_FOUND"

    def test_schema_validation_failure_returns_bad_request(self, mock_server):
        import asyncio
        import mcp.types as types

        handler = mock_server.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="rules.get", arguments={}),
        )
        result = asyncio.run(handler(req))

        assert result.root.isError is True
        payload = json.loads(result.root.content[0].text)
        assert payload["error"]["code"] == "BAD_REQUEST"
        assert payload["error"]["message"] == "Input validation failed"

    def test_build_tools_roundtrip(self, monkeypatch):
        """Verify _build_tools produces correct Tool objects."""
        tools, metadata = server._build_tools(SAMPLE_MANIFEST)

        # All tools are present
        names = [t.name for t in tools]
        assert "issues.list" in names
        assert "stats.assets" in names
        assert "rules.get" in names

        # Metadata is correct
        assert metadata["issues.list"]["trpcProcedure"] == "v2.issues.list"
        assert metadata["stats.assets"]["trpcProcedure"] == "v2.stats.assets"
