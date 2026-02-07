"""
ZeroPath MCP Server

Fetches the tool manifest from the ZeroPath frontend at startup and
dynamically registers MCP tools. All input validation is delegated to
tRPC's server-side Zod schemas — the manifest's JSON Schemas are used
for tool advertisement and best-effort client-side validation. If a tool
schema uses JSON Schema features this client does not support, the server
will skip client-side validation for that request rather than validating
incorrectly.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

from .trpc_client import TrpcClient, load_config
from .jsonschema_validation import UnsupportedSchemaError, validate as validate_jsonschema

JsonObject = dict[str, Any]

_CLIENT: TrpcClient | None = None

_ALLOWED_ORG_ID_BEHAVIORS = {"inject-if-missing", "required", "none"}
_ALLOWED_PROCEDURE_TYPES = {"query", "mutation"}


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


def _apply_org_id(arguments: JsonObject, behavior: str, *, organization_id: str) -> str | None:
    """Inject organizationId from config when appropriate.

    Returns an error message string if org ID is required but missing,
    otherwise returns None (success).
    """
    if behavior == "none":
        return None

    if not arguments.get("organizationId"):
        arguments["organizationId"] = organization_id

    if behavior == "required" and not arguments.get("organizationId"):
        return "organizationId is required"

    return None


def _build_tools(manifest: JsonObject) -> tuple[list[types.Tool], dict[str, JsonObject]]:
    """Parse the manifest into MCP Tool objects and a metadata lookup.

    Returns (tools, metadata) where metadata maps tool name ->
    {"trpcProcedure": str, "procedureType": "query"|"mutation", "orgIdBehavior": str}.
    """
    if not isinstance(manifest, dict):
        raise RuntimeError("Invalid MCP manifest: top-level must be an object")

    version = manifest.get("version")
    if version != 1:
        raise RuntimeError(f"Invalid MCP manifest: unsupported version {version!r}")

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

        trpc_procedure = entry.get("trpcProcedure")
        if not isinstance(trpc_procedure, str) or not trpc_procedure.strip():
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].trpcProcedure must be a non-empty string"
            )

        procedure_type = entry.get("procedureType")
        if not isinstance(procedure_type, str) or procedure_type not in _ALLOWED_PROCEDURE_TYPES:
            raise RuntimeError(
                f"Invalid MCP manifest: tools[{idx}].procedureType must be one of "
                f"{sorted(_ALLOWED_PROCEDURE_TYPES)}"
            )

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

        if org_id_behavior != "none" and not _schema_mentions_property(input_schema, "organizationId"):
            # Don't hard-fail: org ID may be introduced via composition, $ref, etc.
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
            "trpcProcedure": trpc_procedure,
            "procedureType": procedure_type,
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

        error = _apply_org_id(args, meta["orgIdBehavior"], organization_id=client.organization_id)
        if error:
            raise RuntimeError(json.dumps({"error": {"code": "BAD_REQUEST", "message": error}}))

        try:
            issues = validate_jsonschema(args, meta["inputSchema"])
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
            meta["trpcProcedure"],
            args,
            procedure_type=meta["procedureType"],
        )
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(json.dumps(result))
        return [types.TextContent(type="text", text=json.dumps(result))]

    return server
