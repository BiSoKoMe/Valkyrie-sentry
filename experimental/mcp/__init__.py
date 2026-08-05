"""Valkyrie MCP (Model Context Protocol) server — AI-agent interface to the EDR.

See server.py for the protocol layer and tools.py for the capability surface.
Read-only by default; response actions are opt-in and dry-run by default.
"""

from .server import PROTOCOL_VERSION, handle_message, run_stdio, serve
from .tools import TOOLS, ToolContext, call_tool, list_tools

__all__ = [
    "PROTOCOL_VERSION", "handle_message", "run_stdio", "serve",
    "TOOLS", "ToolContext", "call_tool", "list_tools",
]
