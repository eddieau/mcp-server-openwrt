"""Tool orchestrator for the OpenWrt MCP server.

Thin shim. Each OpenWrt operational domain lives in its own
module under `tools/` and exports a `register(mcp)` function.
Adding a new tool means extending the right category module —
never lengthening this file.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from openwrt_mcp.tools import (
    dhcp,
    firewall,
    network,
    opkg,
    service,
    system,
    uci,
    wireless,
)


def register_tools(mcp: FastMCP) -> None:
    dhcp.register(mcp)
    firewall.register(mcp)
    network.register(mcp)
    opkg.register(mcp)
    service.register(mcp)
    system.register(mcp)
    uci.register(mcp)
    wireless.register(mcp)
