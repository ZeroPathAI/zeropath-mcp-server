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

from .jsonschema_validation import UnsupportedSchemaError
from .jsonschema_validation import validate as validate_jsonschema
from .trpc_client import TrpcClient, load_config

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
                "organizationId is required for this operation. Pass organizationId explicitly or set ZEROPATH_ORG_ID."
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
                f"Invalid MCP manifest: tools[{idx}].orgIdBehavior must be one of {sorted(_ALLOWED_ORG_ID_BEHAVIORS)}"
            )

        http_method = entry.get("httpMethod")
        if not isinstance(http_method, str) or not http_method.strip():
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].httpMethod must be a non-empty string")
        http_method = http_method.upper()
        if http_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].httpMethod must be a valid HTTP method")

        http_path = entry.get("httpPath")
        if not isinstance(http_path, str) or not http_path.strip():
            raise RuntimeError(f"Invalid MCP manifest: tools[{idx}].httpPath must be a non-empty string")
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


def _normalize_tool_error_payload(
    result: JsonObject,
    *,
    tool_name: str,
    http_method: str,
    http_path: str,
) -> JsonObject:
    """Ensure tool errors always expose a non-empty string message + rich metadata."""
    raw_error = result.get("error")
    if not isinstance(raw_error, dict):
        raw_error = {"message": raw_error}

    raw_message = raw_error.get("message")
    if isinstance(raw_message, str):
        message = raw_message.strip()
    else:
        message = ""
    if not message:
        message = f"Tool {tool_name} failed"

    normalized: JsonObject = {
        "error": {
            "code": str(raw_error.get("code") or "TOOL_ERROR"),
            "message": message,
        }
    }

    http_status = raw_error.get("httpStatus")
    if http_status is not None:
        normalized["error"]["httpStatus"] = http_status

    data: JsonObject = {}
    raw_data = raw_error.get("data")
    if isinstance(raw_data, dict):
        data.update(raw_data)
    elif raw_data is not None:
        data["rawData"] = raw_data

    data.setdefault("tool", tool_name)
    data.setdefault("httpMethod", http_method)
    data.setdefault("httpPath", http_path)

    if isinstance(raw_message, str) and not raw_message.strip():
        data.setdefault("messageWasEmpty", True)
    elif raw_message is not None and not isinstance(raw_message, str):
        data.setdefault("rawMessage", raw_message)

    normalized["error"]["data"] = data
    return normalized


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
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
        if name not in metadata:
            raise RuntimeError(json.dumps({"error": {"code": "NOT_FOUND", "message": f"Unknown tool: {name}"}}))

        meta = metadata[name]
        args = dict(arguments or {})

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

        try:
            result = await asyncio.to_thread(
                client.call,
                meta["httpPath"],
                args,
                http_method=meta["httpMethod"],
            )
        except Exception as exc:
            detail = str(exc).strip() or repr(exc)
            raise RuntimeError(
                json.dumps(
                    {
                        "error": {
                            "code": "INTERNAL_ERROR",
                            "message": f"Failed to invoke ZeroPath API for tool {name}",
                            "data": {
                                "tool": name,
                                "httpMethod": meta["httpMethod"],
                                "httpPath": meta["httpPath"],
                                "exceptionType": type(exc).__name__,
                                "detail": detail,
                            },
                        }
                    }
                )
            ) from exc

        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(
                json.dumps(
                    _normalize_tool_error_payload(
                        result,
                        tool_name=name,
                        http_method=meta["httpMethod"],
                        http_path=meta["httpPath"],
                    )
                )
            )
        return [types.TextContent(type="text", text=json.dumps(result))]

    return server
