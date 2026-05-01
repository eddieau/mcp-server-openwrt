"""Wireless tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import (
    make_client,
    render,
    validate_iface_name,
    validate_ssid,
    validate_wpa_psk,
)


def _run_iwinfo(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run("iwinfo", timeout=10.0).to_dict()


def _run_iwinfo_assoclist(node_id, auth, ctx, iface: str) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"iwinfo {iface} assoclist -J", timeout=10.0).to_dict()


def _run_set_ssid(node_id, auth, ctx, radio: str, ssid: str) -> dict:
    if err := validate_iface_name(radio, field="radio"):
        return {"exit_code": 2, "stderr": err}
    if err := validate_ssid(ssid):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run(f"uci set wireless.{radio}.ssid={ssid}", timeout=5)
        if r1.exit_code != 0:
            return r1.to_dict()
        r2 = client.run("uci commit wireless", timeout=5)
        return r2.to_dict()


def _run_wireless_restart(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run("/etc/init.d/network restart", timeout=30.0).to_dict()


def _run_set_password(node_id, auth, ctx, radio: str, password: str) -> dict:
    if err := validate_iface_name(radio, field="radio"):
        return {"exit_code": 2, "stderr": err}
    if err := validate_wpa_psk(password):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run(f"uci set wireless.{radio}.key={password}", timeout=5)
        if r1.exit_code != 0:
            return r1.to_dict()
        r2 = client.run("uci commit wireless", timeout=5)
        return r2.to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.check_wifi",
        description="Run `iwinfo` to get WiFi device info and scan results.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def check_wifi(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_iwinfo, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.wireless_get_clients",
        description="List WiFi clients associated to a radio interface via `iwinfo <iface> assoclist -J`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def wireless_get_clients(
        site_id: str,
        node_id: str,
        iface: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_iwinfo_assoclist, node_id, auth, ctx, iface)
        return render(raw)

    @mcp.tool(
        name="openwrt.wireless_get_signal_strength",
        description="Read per-client signal strength (dBm) for a WiFi interface.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def wireless_get_signal_strength(
        site_id: str,
        node_id: str,
        iface: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_iwinfo_assoclist, node_id, auth, ctx, iface)
        return render(raw)

    @mcp.tool(
        name="openwrt.wireless_set_ssid",
        description="Set the SSID of a WiFi radio interface via `uci set` + `uci commit`.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def wireless_set_ssid(
        site_id: str,
        node_id: str,
        radio: str,
        ssid: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_set_ssid, node_id, auth, ctx, radio, ssid)
        return render(raw)

    @mcp.tool(
        name="openwrt.wireless_restart_radio",
        description="Restart the WiFi radio via `/etc/init.d/network restart`.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def wireless_restart_radio(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_wireless_restart, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.wireless_set_password",
        description="Set the WiFi passphrase (pre-shared key) for a radio interface.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def wireless_set_password(
        site_id: str,
        node_id: str,
        radio: str,
        password: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_set_password, node_id, auth, ctx, radio, password
        )
        return render(raw)
