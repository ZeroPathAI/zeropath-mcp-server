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
from zeropath_mcp_server.jsonschema_validation import validate as validate_jsonschema

SAMPLE_MANIFEST_V2 = {
    "version": 2,
    "generatedAt": "2026-01-01T00:00:00.000Z",
    "tools": [
        {
            "name": "issues.list",
            "httpMethod": "POST",
            "httpPath": "/api/v2/issues/search",
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
            "httpMethod": "POST",
            "httpPath": "/api/v2/stats/assets",
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
            "httpMethod": "POST",
            "httpPath": "/api/v2/rules/get",
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

REF_ROOT_SCHEMA = {
    "definitions": {
        "IssuesListInput": {
            "type": "object",
            "properties": {
                "organizationId": {"type": "string"},
                "page": {"type": "integer"},
            },
            "required": ["page"],
        }
    }
}


class TestBuildTools:
    """Test _build_tools with v2 manifest format."""

    def test_rejects_v1(self):
        with pytest.raises(RuntimeError, match="expected 2"):
            server._build_tools({"version": 1, "tools": []})

    def test_parses_tools_from_manifest(self):
        tools, metadata = server._build_tools(SAMPLE_MANIFEST_V2)

        assert len(tools) == 3
        assert tools[0].name == "issues_list"
        assert tools[0].description == "List security issues"

    def test_preserves_http_metadata(self):
        _, metadata = server._build_tools(SAMPLE_MANIFEST_V2)

        assert metadata["issues_list"]["httpMethod"] == "POST"
        assert metadata["issues_list"]["httpPath"] == "/api/v2/issues/search"
        assert metadata["issues_list"]["orgIdBehavior"] == "inject-if-missing"

        assert metadata["stats_assets"]["httpMethod"] == "POST"
        assert metadata["stats_assets"]["httpPath"] == "/api/v2/stats/assets"

        assert metadata["rules_get"]["httpMethod"] == "POST"
        assert metadata["rules_get"]["httpPath"] == "/api/v2/rules/get"

    def test_empty_manifest(self):
        tools, metadata = server._build_tools({"version": 2, "tools": []})
        assert tools == []
        assert metadata == {}


class TestJsonschemaValidation:
    def test_ref_resolution_uses_root_schema_when_provided(self):
        schema = {"$ref": "#/definitions/IssuesListInput"}
        issues = validate_jsonschema({"organizationId": "org_test"}, schema, root_schema=REF_ROOT_SCHEMA)
        assert any(i.path == "page" and "Missing required" in i.message for i in issues)


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

    def test_required_errors_when_config_empty(self):
        args = {}
        error = server._apply_org_id(args, "required", organization_id="")
        assert error is not None
        assert "organizationId is required" in error

    def test_inject_if_missing_skips_when_org_id_none(self):
        args = {"page": 1}
        error = server._apply_org_id(args, "inject-if-missing", organization_id=None)
        assert error is None
        assert "organizationId" not in args

    def test_required_errors_when_org_id_none(self):
        args = {}
        error = server._apply_org_id(args, "required", organization_id=None)
        assert error is not None
        assert "organizationId is required" in error
        assert "organizationId" not in args

    def test_required_preserves_existing(self):
        args = {"organizationId": "org_custom"}
        error = server._apply_org_id(args, "required", organization_id=None)
        assert error is None
        assert args["organizationId"] == "org_custom"

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


class TestRestClient:
    """Test TrpcClient calling REST endpoints (v2 manifest pattern)."""

    def test_rest_post_builds_url_and_headers(self, monkeypatch):
        captured = {}

        def fake_request(method, url, headers=None, json=None, timeout=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return DummyResponse({"issues": [], "totalCount": 0})

        monkeypatch.setattr(trpc_client.requests, "request", fake_request)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "/api/v2/issues/search",
            {"organizationId": "org_test"},
            http_method="POST",
        )

        assert result == {"issues": [], "totalCount": 0}
        assert captured["method"] == "POST"
        assert captured["url"] == "https://example.com/api/v2/issues/search"
        assert captured["headers"]["X-ZeroPath-API-Token-Id"] == "test-token-id"
        assert captured["headers"]["X-ZeroPath-API-Token-Secret"] == "test-token-secret"
        assert captured["headers"]["X-ZeroPath-Client"] == "zeropath-mcp-server"
        assert captured["json"]["organizationId"] == "org_test"

    def test_rest_error_returns_error_dict(self, monkeypatch):
        def fake_request(method, url, headers=None, json=None, timeout=None):
            return DummyResponse({"error": "Unauthorized"}, status_code=401)

        monkeypatch.setattr(trpc_client.requests, "request", fake_request)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "/api/v2/repositories/list",
            {},
            http_method="POST",
        )
        assert "error" in result
        assert result["error"]["code"] == "API_ERROR"
        assert result["error"]["message"] == "Unauthorized"
        assert result["error"]["httpStatus"] == 401

    def test_rest_error_with_nested_message_is_extracted(self, monkeypatch):
        def fake_request(method, url, headers=None, json=None, timeout=None):
            return DummyResponse(
                {"error": {"message": "JWT expired", "code": "UNAUTHORIZED", "requestId": "req_123"}},
                status_code=401,
            )

        monkeypatch.setattr(trpc_client.requests, "request", fake_request)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call("/api/v2/issues/search", {}, http_method="POST")

        assert result["error"]["code"] == "API_ERROR"
        assert result["error"]["message"] == "JWT expired"
        assert result["error"]["httpStatus"] == 401
        assert result["error"]["data"]["apiCode"] == "UNAUTHORIZED"
        assert result["error"]["data"]["requestId"] == "req_123"

    def test_rest_error_empty_message_falls_back_to_http_status(self, monkeypatch):
        def fake_request(method, url, headers=None, json=None, timeout=None):
            return DummyResponse({"error": ""}, status_code=500)

        monkeypatch.setattr(trpc_client.requests, "request", fake_request)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call("/api/v2/issues/search", {}, http_method="POST")

        assert result["error"]["code"] == "API_ERROR"
        assert result["error"]["message"] == "ZeroPath API returned HTTP 500"
        assert result["error"]["httpStatus"] == 500
        assert result["error"]["data"]["emptyErrorField"] is True

    def test_rest_post_includes_chatkit_token_header(self, monkeypatch):
        monkeypatch.delenv("ZEROPATH_TOKEN_ID", raising=False)
        monkeypatch.delenv("ZEROPATH_TOKEN_SECRET", raising=False)
        monkeypatch.delenv("ZEROPATH_SESSION_COOKIE", raising=False)
        monkeypatch.setenv("ZEROPATH_CHATKIT_TOKEN", "chatkit-token-value")
        monkeypatch.setenv("ZEROPATH_BASE_URL", "https://example.com")

        captured = {}

        def fake_request(method, url, headers=None, json=None, timeout=None):
            captured["headers"] = headers
            return DummyResponse({"issues": [], "totalCount": 0})

        monkeypatch.setattr(trpc_client.requests, "request", fake_request)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.call(
            "/api/v2/issues/search",
            {"organizationId": "org_test"},
            http_method="POST",
        )

        assert result == {"issues": [], "totalCount": 0}
        assert captured["headers"]["X-ZeroPath-ChatKit-Token"] == "chatkit-token-value"


class TestLoadConfig:
    def test_accepts_session_cookie_auth(self, monkeypatch):
        monkeypatch.delenv("ZEROPATH_TOKEN_ID", raising=False)
        monkeypatch.delenv("ZEROPATH_TOKEN_SECRET", raising=False)
        monkeypatch.delenv("ZEROPATH_CHATKIT_TOKEN", raising=False)
        monkeypatch.setenv("ZEROPATH_SESSION_COOKIE", "zp_session=session-value")
        monkeypatch.setenv("ZEROPATH_BASE_URL", "https://example.com")

        cfg = trpc_client.load_config()
        assert cfg.session_cookie == "zp_session=session-value"
        assert cfg.token_id is None
        assert cfg.token_secret is None

    def test_accepts_chatkit_token_auth(self, monkeypatch):
        monkeypatch.delenv("ZEROPATH_TOKEN_ID", raising=False)
        monkeypatch.delenv("ZEROPATH_TOKEN_SECRET", raising=False)
        monkeypatch.delenv("ZEROPATH_SESSION_COOKIE", raising=False)
        monkeypatch.setenv("ZEROPATH_CHATKIT_TOKEN", "chatkit-token-value")
        monkeypatch.setenv("ZEROPATH_BASE_URL", "https://example.com")

        cfg = trpc_client.load_config()
        assert cfg.chatkit_token == "chatkit-token-value"
        assert cfg.token_id is None
        assert cfg.token_secret is None

    def test_rejects_ambiguous_auth_modes(self, monkeypatch):
        monkeypatch.setenv("ZEROPATH_TOKEN_ID", "token-id")
        monkeypatch.setenv("ZEROPATH_TOKEN_SECRET", "token-secret")
        monkeypatch.setenv("ZEROPATH_CHATKIT_TOKEN", "chatkit-token-value")
        monkeypatch.delenv("ZEROPATH_SESSION_COOKIE", raising=False)

        with pytest.raises(OSError, match="Ambiguous credentials"):
            trpc_client.load_config()


class TestFetchManifest:
    def test_successful_fetch_v2(self, monkeypatch):
        def fake_get(url, headers=None, timeout=None):
            return DummyResponse(SAMPLE_MANIFEST_V2)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        result = client.fetch_manifest()
        assert result["version"] == 2
        assert len(result["tools"]) == 3

    def test_rejects_v1(self, monkeypatch):
        def fake_get(url, headers=None, timeout=None):
            return DummyResponse({"version": 1, "tools": []})

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        with pytest.raises(RuntimeError, match="Unsupported manifest version"):
            client.fetch_manifest()

    def test_rejects_bad_version(self, monkeypatch):
        def fake_get(url, headers=None, timeout=None):
            return DummyResponse({"version": 99, "tools": []})

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        with pytest.raises(RuntimeError, match="Unsupported manifest version"):
            client.fetch_manifest()

    def test_rejects_http_error(self, monkeypatch):
        def fake_get(url, headers=None, timeout=None):
            return DummyResponse("Not Found", status_code=404)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        client = trpc_client.TrpcClient(trpc_client.load_config())
        with pytest.raises(RuntimeError, match="HTTP 404"):
            client.fetch_manifest()


class TestCallTool:
    """Test the call_tool handler via create_server()."""

    @pytest.fixture
    def mock_server_v2(self, monkeypatch):
        """Create a server with a mocked v2 manifest fetch."""

        def fake_get(url, headers=None, timeout=None):
            return DummyResponse(SAMPLE_MANIFEST_V2)

        monkeypatch.setattr(trpc_client.requests, "get", fake_get)

        # Reset cached client so each test gets a fresh server
        server._CLIENT = None
        srv = server.create_server()
        yield srv
        server._CLIENT = None

    def test_unknown_tool_returns_error(self, mock_server_v2):
        import asyncio

        import mcp.types as types

        handler = mock_server_v2.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="no.such.tool", arguments=None),
        )
        result = asyncio.run(handler(req))

        assert result.root.isError is True
        assert len(result.root.content) == 1
        payload = json.loads(result.root.content[0].text)
        assert payload["error"]["code"] == "NOT_FOUND"

    def test_schema_validation_failure_returns_bad_request(self, mock_server_v2):
        import asyncio

        import mcp.types as types

        handler = mock_server_v2.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="rules_get", arguments={}),
        )
        result = asyncio.run(handler(req))

        assert result.root.isError is True
        payload = json.loads(result.root.content[0].text)
        assert payload["error"]["code"] == "BAD_REQUEST"
        assert payload["error"]["message"] == "Input validation failed"

    def test_tool_error_payload_normalizes_empty_message(self, mock_server_v2, monkeypatch):
        import asyncio

        import mcp.types as types

        client = server._get_client()

        def fake_call(http_path, payload, *, http_method="POST"):
            return {
                "error": {
                    "code": "API_ERROR",
                    "message": "",
                    "httpStatus": 500,
                    "data": {"requestId": "req_999"},
                }
            }

        monkeypatch.setattr(client, "call", fake_call)

        handler = mock_server_v2.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="issues_list", arguments={}),
        )
        result = asyncio.run(handler(req))

        assert result.root.isError is True
        payload = json.loads(result.root.content[0].text)
        assert payload["error"]["code"] == "API_ERROR"
        assert payload["error"]["message"] == "Tool issues_list failed"
        assert payload["error"]["httpStatus"] == 500
        assert payload["error"]["data"]["requestId"] == "req_999"
        assert payload["error"]["data"]["messageWasEmpty"] is True
        assert payload["error"]["data"]["httpPath"] == "/api/v2/issues/search"
        assert payload["error"]["data"]["httpMethod"] == "POST"

    def test_build_tools_v2_roundtrip(self):
        """Verify _build_tools produces correct Tool objects for v2."""
        tools, metadata = server._build_tools(SAMPLE_MANIFEST_V2)

        names = [t.name for t in tools]
        assert "issues_list" in names
        assert "stats_assets" in names
        assert "rules_get" in names

        assert metadata["issues_list"]["httpPath"] == "/api/v2/issues/search"
        assert metadata["issues_list"]["httpMethod"] == "POST"
        assert metadata["stats_assets"]["httpPath"] == "/api/v2/stats/assets"
