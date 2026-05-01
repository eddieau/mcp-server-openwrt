"""FastMCP entry point for the OpenWrt MCP server.

Dual-mode auth:
  - Standalone / Claude Desktop: OPENWRT_HOST + OPENWRT_USER +
    OPENWRT_PASS environment variables
  - Embedded mode (host project injects per-call): `auth` argument
    on each tool call (`{username, password}`); env vars unused

Dual-mode transport:
  - Standalone / Claude Desktop: stdio (default; no env needed)
  - Containerised / HTTP server: streamable-HTTP via env vars
      MCP_TRANSPORT=streamable-http
      MCP_HOST=0.0.0.0
      MCP_PORT=8002
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from openwrt_mcp.server import register_tools

mcp = FastMCP(
    "openwrt-mcp",
    host=os.environ.get("MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("MCP_PORT", "8002")),
)

register_tools(mcp)


def main() -> None:
    """Run the MCP server.

    Transport defaults to stdio (Claude Desktop / CLI). Set
    MCP_TRANSPORT=streamable-http for HTTP server mode (containerised
    or embedded behind a host gateway).
    """
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport not in ("stdio", "sse", "streamable-http"):
        raise SystemExit(
            f"MCP_TRANSPORT={transport!r} not supported. "
            "Use stdio | sse | streamable-http."
        )
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
