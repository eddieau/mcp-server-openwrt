"""OpenWrt MCP tools — one module per operational domain.

Domain modules are explicit re-exports so consumers (and the
register_tools dispatcher in server.py) can `from openwrt_mcp.tools
import dhcp` and so on. The `as` aliasing satisfies ruff F401.
"""

from __future__ import annotations

from openwrt_mcp.tools import dhcp as dhcp
from openwrt_mcp.tools import firewall as firewall
from openwrt_mcp.tools import network as network
from openwrt_mcp.tools import opkg as opkg
from openwrt_mcp.tools import service as service
from openwrt_mcp.tools import system as system
from openwrt_mcp.tools import uci as uci
from openwrt_mcp.tools import wireless as wireless

__all__ = [
    "dhcp",
    "firewall",
    "network",
    "opkg",
    "service",
    "system",
    "uci",
    "wireless",
]
