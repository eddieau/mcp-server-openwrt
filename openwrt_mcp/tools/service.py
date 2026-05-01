"""Service control tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio
import enum

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import make_client, render


class ServiceAction(str, enum.Enum):
    enable = "enable"
    disable = "disable"
    start = "start"
    stop = "stop"
    restart = "restart"
    status = "status"
    reload = "reload"


_KNOWN_SERVICES = frozenset(
    {
        "network",
        "firewall",
        "dnsmasq",
        "dropbear",
        "uhttpd",
        "system",
        "odhcpd",
        "log",
    }
)


def _run_service_action(node_id, auth, ctx, service: str, action: str) -> dict:
    if service not in _KNOWN_SERVICES:
        return {
            "exit_code": 2,
            "stderr": f"Unknown service '{service}'. Allowed: {', '.join(sorted(_KNOWN_SERVICES))}",
        }
    try:
        ServiceAction(action)
    except ValueError:
        valid = [a.value for a in ServiceAction]
        return {
            "exit_code": 2,
            "stderr": f"Invalid action '{action}'. Allowed: {', '.join(valid)}",
        }
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"/etc/init.d/{service} {action}", timeout=30.0).to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.service_action",
        description="Invoke an init script action on an OpenWrt service (enable/disable/start/stop/restart/status/reload).",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
        meta={},
    )
    async def service_action(
        site_id: str,
        node_id: str,
        service: str,
        action: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_service_action, node_id, auth, ctx, service, action
        )
        return render(raw)
