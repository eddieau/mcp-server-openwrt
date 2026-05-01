"""System tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import make_client, render


def _run_reboot_router(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        client.fire_and_forget("reboot")
    return {
        "initiated": True,
        "note": "Reboot command issued; router unreachable for ~30-90s.",
    }


def _run_uptime(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("cat /proc/uptime", timeout=5.0).to_dict()
    try:
        parts = raw.get("stdout", "0 0").strip().split()
        uptime = float(parts[0])
        idle = float(parts[1]) if len(parts) > 1 else 0.0
        return {
            "uptime_seconds": int(uptime),
            "idle_seconds": int(idle),
            "exit_code": raw.get("exit_code", 0),
        }
    except (ValueError, IndexError):
        return {"uptime_seconds": 0, "idle_seconds": 0, "exit_code": 1}


def _run_loadavg(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("cat /proc/loadavg", timeout=5.0).to_dict()
    try:
        parts = raw.get("stdout", "0 0 0 0/0 0").strip().split()
        return {
            "load_1m": float(parts[0]),
            "load_5m": float(parts[1]),
            "load_15m": float(parts[2]),
            "exit_code": raw.get("exit_code", 0),
        }
    except (ValueError, IndexError):
        return {"load_1m": 0.0, "load_5m": 0.0, "load_15m": 0.0, "exit_code": 1}


def _run_meminfo(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("cat /proc/meminfo", timeout=5.0).to_dict()
    result = {
        "mem_total_kb": 0,
        "mem_total_bytes": 0,
        "mem_available_kb": 0,
        "mem_available_bytes": 0,
        "mem_free_kb": 0,
        "mem_free_bytes": 0,
        "mem_buffers_kb": 0,
        "mem_buffers_bytes": 0,
        "exit_code": raw.get("exit_code", 0),
    }
    for line in raw.get("stdout", "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        key = parts[0].rstrip(":")
        try:
            val = int(parts[1])
        except ValueError:
            continue
        if key == "MemTotal:":
            result["mem_total_kb"] = val
            result["mem_total_bytes"] = val * 1024
        elif key == "MemAvailable:":
            result["mem_available_kb"] = val
            result["mem_available_bytes"] = val * 1024
        elif key == "MemFree:":
            result["mem_free_kb"] = val
            result["mem_free_bytes"] = val * 1024
        elif key == "Buffers:":
            result["mem_buffers_kb"] = val
            result["mem_buffers_bytes"] = val * 1024
    return result


def _run_ps_count(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("ps | tail -n +2 | wc -l", timeout=5.0).to_dict()
    try:
        count = int(raw.get("stdout", "0").strip())
        return {"process_count": count, "exit_code": raw.get("exit_code", 0)}
    except ValueError:
        return {"process_count": 0, "exit_code": 1}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.reboot_router",
        description="Reboot the OpenWrt router (fire-and-forget).",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
        meta={},
    )
    async def reboot_router(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_reboot_router, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.system_get_uptime",
        description="Read system uptime from /proc/uptime.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def system_get_uptime(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_uptime, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.system_get_load",
        description="Read system load averages from /proc/loadavg.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def system_get_load(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_loadavg, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.system_get_memory",
        description="Read system memory info from /proc/meminfo.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def system_get_memory(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_meminfo, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.system_get_processes",
        description="Count running processes via `ps | tail -n +2 | wc -l`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def system_get_processes(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_ps_count, node_id, auth, ctx)
        return render(raw)
