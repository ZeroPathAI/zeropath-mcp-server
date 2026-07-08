"""
ZeroPath MCP Server

Interact with your product security findings using natural language.
"""

__version__ = "0.2.0"

__all__ = ["mcp", "__version__"]


def __getattr__(name):
    # `server` validates credentials at import time, so it is imported
    # lazily: `from zeropath_mcp_server import mcp` still works for the
    # legacy entry point, while credential-free submodules (tools, tests)
    # stay importable without the environment configured.
    if name == "mcp":
        from .server import mcp

        return mcp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
