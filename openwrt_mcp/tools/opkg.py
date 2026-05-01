"""opkg package manager tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio
import re

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import make_client, render

_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]*\Z")


def _run_opkg_list(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run("opkg list", timeout=30.0).to_dict()


def _run_opkg_install(node_id, auth, ctx, package: str) -> dict:
    if not _PKG_NAME_RE.match(package):
        return {"exit_code": 2, "stderr": f"Invalid package name '{package}'"}
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"opkg install {package}", timeout=120.0).to_dict()


def _run_opkg_remove(node_id, auth, ctx, package: str) -> dict:
    if not _PKG_NAME_RE.match(package):
        return {"exit_code": 2, "stderr": f"Invalid package name '{package}'"}
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"opkg remove {package}", timeout=120.0).to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.opkg_list",
        description="List all available and installed opkg packages.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def opkg_list(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_opkg_list, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.opkg_install",
        description="Install an opkg package.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
        meta={},
    )
    async def opkg_install(
        site_id: str,
        node_id: str,
        package: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_opkg_install, node_id, auth, ctx, package)
        return render(raw)

    @mcp.tool(
        name="openwrt.opkg_remove",
        description="Remove an installed opkg package.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
        meta={},
    )
    async def opkg_remove(
        site_id: str,
        node_id: str,
        package: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_opkg_remove, node_id, auth, ctx, package)
        return render(raw)
