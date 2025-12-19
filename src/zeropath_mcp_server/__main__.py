"""
Entry point for running the MCP server.

Usage:
    python -m zeropath_mcp_server
    zeropath-mcp-server
"""

from .server import mcp


def main():
    """Run the MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
