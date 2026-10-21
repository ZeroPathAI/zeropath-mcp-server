import asyncio
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
from threading import Thread

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent


def test_installed_server_discovers_and_calls_tools_over_stdio():
    observed: list[dict[str, object]] = []
    manifest = {
        "version": 2,
        "tools": [
            {
                "name": "fixture.echo",
                "description": "Local transport fixture",
                "httpMethod": "POST",
                "httpPath": "/api/v2/fixture/echo",
                "orgIdBehavior": "required",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "organizationId": {"type": "string"},
                        "value": {"type": "string"},
                    },
                    "required": ["organizationId", "value"],
                    "additionalProperties": False,
                },
            }
        ],
    }

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, payload: object) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            observed.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "token": self.headers.get("X-ZeroPath-MCP-Token"),
                }
            )
            self.respond(manifest)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            observed.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "token": self.headers.get("X-ZeroPath-MCP-Token"),
                    "body": body,
                }
            )
            self.respond({"value": body["value"]})

    async def verify(base_url: str) -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "zeropath_mcp_server"],
            env={
                "ZEROPATH_BASE_URL": base_url,
                "ZEROPATH_MCP_TOKEN": "fixture-token",
                "ZEROPATH_ORG_ID": "fixture-org",
            },
        )
        async with (
            asyncio.timeout(30),
            stdio_client(parameters) as (reader, writer),
            ClientSession(
                reader, writer, read_timeout_seconds=timedelta(seconds=10)
            ) as client,
        ):
            await client.initialize()
            tools = (await client.list_tools()).tools
            assert [tool.name for tool in tools] == ["fixture_echo"]
            assert "organizationId" not in tools[0].inputSchema["properties"]
            result = await client.call_tool("fixture_echo", {"value": "verified"})
            assert not result.isError
            assert len(result.content) == 1
            assert isinstance(result.content[0], TextContent)
            assert json.loads(result.content[0].text) == {"value": "verified"}

    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            asyncio.run(verify(f"http://127.0.0.1:{server.server_port}"))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()

    assert observed == [
        {"method": "GET", "path": "/mcp-manifest.json", "token": "fixture-token"},
        {
            "method": "POST",
            "path": "/api/v2/fixture/echo",
            "token": "fixture-token",
            "body": {"organizationId": "fixture-org", "value": "verified"},
        },
    ]
