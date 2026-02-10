"""
ZeroPath MCP Server

Fetches the tool manifest from the ZeroPath frontend at startup and
dynamically registers MCP tools. All input validation is delegated to
the server-side Zod schemas — the manifest's JSON Schemas are used
for tool advertisement and best-effort client-side validation. If a tool
schema uses JSON Schema features this client does not support, the server
will skip client-side validation for that request rather than validating
incorrectly.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

from .trpc_client import TrpcClient, load_config
from .jsonschema_validation import UnsupportedSchemaError, validate as validate_jsonschema

JsonObject = dict[str, Any]

_CLIENT: TrpcClient | None = None

_ALLOWED_ORG_ID_BEHAVIORS = {"inject-if-missing", "required", "none"}


def _get_client() -> TrpcClient:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = TrpcClient(load_config())
    return _CLIENT


def _schema_mentions_property(schema: Any, prop: str) -> bool:
    """Best-effort check for property existence in a JSON Schema node."""
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict) and prop in props:
            return True
        for v in schema.values():
            if _schema_mentions_property(v, prop):
                return True
    elif isinstance(schema, list):
        for v in schema:
            if _schema_mentions_property(v, prop):
                return True
    return False


def _apply_org_id(arguments: JsonObject, behavior: str, *, organization_id: str | None) -> str | None:
    """Inject organizationId from config when appropriate.

    When *organization_id* is None (ZEROPATH_ORG_ID not configured), injection
    is skipped and server-side resolution is expected to handle it.

    Returns an error message string on failure, otherwise None (success).
    """
    if behavior == "none":
        return None

    if not arguments.get("organizationId"):
        # Only inject non-empty values. Treat empty string as "not configured".
        if organization_id:
            arguments["organizationId"] = organization_id
        elif behavior == "required":
            return (
                "organizationId is required for this operation. "
                "Pass organizationId explicitly or set ZEROPATH_ORG_ID."
            )

    return None


def _build_tools(manifest: JsonObject) -> tuple[list[types.Tool], dict[str, JsonObject]]:
    """Parse the manifest into MCP Tool objects and a metadata lookup.

    Supports manifest v2 only (httpMethod/httpPath). The metadata lookup
    includes keys: httpMethod, httpPath, orgIdBehavior, inputSchema.
    """
    if not isinstance(manifest, dict):
        raise RuntimeError("Invalid MCP manifest: top-level must be an object")

    version = manifest.get("version")
    if version != 2:
        raise RuntimeError(f"Invalid MCP manifest: unsupported version {version!r} (expected 2)")

    raw_tools = manifest.get("tools")
    if not isinstance(raw_tools, list):
        raise RuntimeError("Invalid MCP manifest: tools must be a list")

    tools: list[types.Tool] = []
    metadata: dict[str, JsonObject] = {}

    for idx, entry in enumerate(raw_tools):
        if not isinstance(entry, dict):
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}] must be an object")

        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].name must be a non-empty string")

        # OpenAI's API requires tool names to match ^[a-zA-Z0-9_-]+$.
        # The manifest uses operationIds like "issues.list" which contain dots.
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)

        input_schema = entry.get("inputSchema")
        if not isinstance(input_schema, dict):
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].inputSchema must be an object")

        description = entry.get("description", "")
        if not isinstance(description, str):
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].description must be a string")

        org_id_behavior = entry.get("orgIdBehavior", "none")
        if not isinstance(org_id_behavior, str) or org_id_behavior not in _ALLOWED_ORG_ID_BEHAVIORS:
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].orgIdBehavior must be one of "
                f"{sorted(_ALLOWED_ORG_ID_BEHAVIORS)}"
            )

        http_method = entry.get("httpMethod")
        if not isinstance(http_method, str) or not http_method.strip():
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].httpMethod must be a non-empty string"
            )
        http_method = http_method.upper()
        if http_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].httpMethod must be a valid HTTP method"
            )

        http_path = entry.get("httpPath")
        if not isinstance(http_path, str) or not http_path.strip():
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].httpPath must be a non-empty string"
            )
        if not http_path.startswith("/api/v2/"):
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].httpPath must start with '/api/v2/' (got {http_path!r})"
            )

        if org_id_behavior != "none" and not _schema_mentions_property(input_schema, "organizationId"):
            print(
                f"Warning: tool {name!r} has orgIdBehavior={org_id_behavior!r} but inputSchema "
                f"does not appear to mention organizationId",
                file=sys.stderr,
            )

        if name in metadata:
            raise RuntimeError(f"Invalid MCP manifest: duplicate tool name {name!r}")

        tools.append(
            types.Tool(
                name=name,
                description=description,
                inputSchema=input_schema,
            )
        )
        metadata[name] = {
            "httpMethod": http_method,
            "httpPath": http_path,
            "orgIdBehavior": org_id_behavior,
            "inputSchema": input_schema,
        }

    return tools, metadata


def create_server() -> Server:
    """Create and return the MCP server with manifest-driven tools."""
    client = _get_client()
    manifest = client.fetch_manifest()
    tools, metadata = _build_tools(manifest)

    server = Server("zeropath")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return tools

    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent]:
        if name not in metadata:
            raise RuntimeError(
                json.dumps({"error": {"code": "NOT_FOUND", "message": f"Unknown tool: {name}"}})
            )

        meta = metadata[name]
        args = dict(arguments or {})

        # Extract the reserved _cookies field injected by CookieInjectingMCPServer.
        # This is the user's raw Cookie header for session-based auth.
        cookies: str | None = args.pop("_cookies", None) or None

        error = _apply_org_id(args, meta["orgIdBehavior"], organization_id=client.organization_id)
        if error:
            raise RuntimeError(json.dumps({"error": {"code": "BAD_REQUEST", "message": error}}))

        try:
            issues = validate_jsonschema(args, meta["inputSchema"], root_schema=manifest)
        except UnsupportedSchemaError as exc:
            # Best-effort validation: don't reject calls due to missing client support
            # for a schema feature; the server-side Zod schema remains authoritative.
            print(
                f"Warning: skipping client-side validation for tool {name!r}: {exc}",
                file=sys.stderr,
            )
            issues = []

        if issues:
            raise RuntimeError(
                json.dumps(
                    {
                        "error": {
                            "code": "BAD_REQUEST",
                            "message": "Input validation failed",
                            "data": {"issues": [i.to_dict() for i in issues]},
                        }
                    }
                )
            )

        result = await asyncio.to_thread(
            client.call,
            meta["httpPath"],
            args,
            http_method=meta["httpMethod"],
            cookies=cookies,
        )
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(json.dumps(result))
        return [types.TextContent(type="text", text=json.dumps(result))]

    return server
