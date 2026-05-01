"""Network tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio
import os
import re

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import (
    make_client,
    render,
    validate_iface_name,
    validate_ipv4,
)

_ARP_RE = re.compile(r"^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+).*$")


def _parse_arp_lines(stdout: str) -> list[dict]:
    entries = []
    for line in stdout.strip().splitlines():
        m = _ARP_RE.match(line)
        if m:
            entries.append(
                {
                    "ip": m.group(1),
                    "iface": m.group(2),
                    "mac": m.group(3),
                }
            )
    return entries


def _run_ifstatus_wan(node_id, auth, ctx) -> dict:
    import json as _json

    with make_client(node_id, auth, ctx) as client:
        raw = client.run("ifstatus wan", timeout=10.0).to_dict()
    try:
        parsed = _json.loads(raw.get("stdout", "") or "{}")
    except _json.JSONDecodeError:
        parsed = {}
    return {
        "command": raw.get("command"),
        "exit_code": raw.get("exit_code"),
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "duration_s": raw.get("duration_s"),
        **parsed,
    }


def _run_check_gateway_sync(node_id, auth, ctx) -> tuple[dict, dict]:
    """Run two probes in sequence over a single SSH session.

    Ping target is configurable via `OPENWRT_PING_TARGET` env var (default
    8.8.8.8). Some networks block public DNS resolvers — operators in
    those environments should set this to a known-reachable upstream.
    """
    import json as _json

    ping_target = os.environ.get("OPENWRT_PING_TARGET", "8.8.8.8")
    with make_client(node_id, auth, ctx) as client:
        lan_raw = client.run("ifstatus lan", timeout=10.0).to_dict()
        upstream_raw = client.run(
            f"ping -c 1 -W 2 {ping_target}", timeout=10.0
        ).to_dict()
    try:
        lan_parsed = _json.loads(lan_raw.get("stdout", "") or "{}")
    except _json.JSONDecodeError:
        lan_parsed = {}
    lan_status = {
        "command": lan_raw.get("command"),
        "exit_code": lan_raw.get("exit_code"),
        "stdout": lan_raw.get("stdout", ""),
        "stderr": lan_raw.get("stderr", ""),
        "duration_s": lan_raw.get("duration_s"),
        # Parsed ifstatus JSON merged at top level — no nested
        # `ifstatus_lan.ifstatus_lan.X` confusion.
        **({"parsed": lan_parsed} if lan_parsed else {}),
    }
    return lan_status, upstream_raw


def _run_restart_wan(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run("ifdown wan && ifup wan", timeout=30.0).to_dict()


def _run_ubus_dump(node_id, auth, ctx) -> dict:
    import json as _json

    with make_client(node_id, auth, ctx) as client:
        raw = client.run("ubus call network.interface dump", timeout=10.0).to_dict()
    try:
        parsed = _json.loads(raw.get("stdout", "") or "{}")
    except _json.JSONDecodeError:
        parsed = {}
    return {
        "command": raw.get("command"),
        "exit_code": raw.get("exit_code"),
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "duration_s": raw.get("duration_s"),
        **parsed,
    }


def _run_ip_route_json(node_id, auth, ctx) -> dict:
    import json as _json

    with make_client(node_id, auth, ctx) as client:
        raw = client.run("ip -j route", timeout=10.0).to_dict()
    try:
        parsed = _json.loads(raw.get("stdout", "") or "[]")
    except _json.JSONDecodeError:
        parsed = []
    return {
        "command": raw.get("command"),
        "exit_code": raw.get("exit_code"),
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "duration_s": raw.get("duration_s"),
        "routes": parsed,
    }


def _run_ip_neigh(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("ip -4 neigh show", timeout=10.0).to_dict()
    return {
        "command": raw.get("command"),
        "exit_code": raw.get("exit_code"),
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "duration_s": raw.get("duration_s"),
        "entries": _parse_arp_lines(raw.get("stdout", "")),
    }


def _run_set_interface_ip(node_id, auth, ctx, iface: str, ip: str) -> dict:
    if err := validate_iface_name(iface):
        return {"exit_code": 2, "stderr": err}
    if err := validate_ipv4(ip):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run(f"uci set network.{iface}.ipaddr={ip}", timeout=5)
        if r1.exit_code != 0:
            return r1.to_dict()
        r2 = client.run("uci commit network", timeout=5)
        return r2.to_dict()


def _run_restart_interface(node_id, auth, ctx, iface: str) -> dict:
    if err := validate_iface_name(iface):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"ifdown {iface} && ifup {iface}", timeout=30.0).to_dict()


def _run_cat_resolv_conf(node_id, auth, ctx) -> dict:
    path = os.environ.get("OPENWRT_RESOLV_CONF", "/tmp/resolv.conf.d/resolv.conf.auto")
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"cat {path}", timeout=5.0).to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.check_wan",
        description="Probe the WAN interface via `ifstatus wan`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def check_wan(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_ifstatus_wan, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.check_gateway",
        description="Probe LAN interface + upstream gateway reachability.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def check_gateway(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        lan_raw, upstream_raw = await asyncio.to_thread(
            _run_check_gateway_sync, node_id, auth, ctx
        )
        return render({"ifstatus_lan": lan_raw, "ping_upstream": upstream_raw})

    @mcp.tool(
        name="openwrt.restart_wan",
        description="Bounce the WAN interface via `ifdown wan && ifup wan`.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def restart_wan(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_restart_wan, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.network_get_interfaces",
        description="Dump all network interface states via `ubus call network.interface dump`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def network_get_interfaces(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_ubus_dump, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.network_get_routes",
        description="Read the routing table via `ip -j route`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def network_get_routes(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_ip_route_json, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.network_get_arp_table",
        description="Read the ARP/neighbour table via `ip -4 neigh show`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def network_get_arp_table(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_ip_neigh, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.network_set_interface_ip",
        description="Set a static IP on an interface via `uci set` + `uci commit`.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def network_set_interface_ip(
        site_id: str,
        node_id: str,
        iface: str,
        ip: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_set_interface_ip, node_id, auth, ctx, iface, ip
        )
        return render(raw)

    @mcp.tool(
        name="openwrt.network_restart_interface",
        description="Bounce a network interface via `ifdown <iface> && ifup <iface>`.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def network_restart_interface(
        site_id: str,
        node_id: str,
        iface: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_restart_interface, node_id, auth, ctx, iface)
        return render(raw)

    @mcp.tool(
        name="openwrt.network_get_dns_resolvers",
        description="Read DNS resolver configuration from /tmp/resolv.conf.d/resolv.conf.auto.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def network_get_dns_resolvers(
        site_id: str, node_id: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_cat_resolv_conf, node_id, auth, ctx)
        return render(raw)
