"""
Legacy entry point for backwards compatibility.

This file is kept for backwards compatibility with existing configurations.
The actual implementation has moved to src/zeropath_mcp_server/server.py

For new installations, use:
    python -m zeropath_mcp_server
or:
    zeropath-mcp-server
"""

from zeropath_mcp_server.__main__ import main

if __name__ == "__main__":
    main()
