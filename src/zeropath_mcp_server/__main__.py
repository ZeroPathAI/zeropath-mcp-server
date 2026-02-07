"""
Entry point for running the MCP server.

Usage:
    python -m zeropath_mcp_server
    zeropath-mcp-server
"""
import asyncio

from mcp.server.stdio import stdio_server

from .server import create_server


async def _run() -> None:
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Run the MCP server."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
