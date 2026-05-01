"""DHCP tools for the OpenWrt MCP server."""

from __future__ import annotations

import asyncio
import json
import re

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, ToolAnnotations

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import (
    _detect_uci_json_support,
    _restructure_uci_text,
    make_client,
    parse_uci_show,
    render,
    validate_hostname,
    validate_iface_name,
    validate_ipv4,
    validate_mac,
)

_LEASE_RE = re.compile(r"^\S+\s+([0-9a-fA-F:]+)\s+(\S+)\s+(\S*)\s+(\S*).*$")


def _parse_leases(text: str) -> list[dict]:
    """Parse /tmp/dhcp.leases: timestamp MAC IP hostname client-id"""
    leases = []
    for line in text.strip().splitlines():
        m = _LEASE_RE.match(line)
        if m:
            mac, ip, hostname, client_id = m.groups()
            leases.append(
                {
                    "timestamp": 0,
                    "mac": mac.lower(),
                    "ip": ip,
                    "hostname": hostname or "",
                    "client_id": client_id or "",
                }
            )
        elif line.strip():
            leases.append(
                {
                    "timestamp": 0,
                    "mac": "",
                    "ip": "",
                    "hostname": "",
                    "client_id": "",
                }
            )
    return leases


def _run_cat_leases(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        raw = client.run("cat /tmp/dhcp.leases", timeout=10.0).to_dict()
    leases = _parse_leases(raw.get("stdout", ""))
    return {
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "exit_code": raw.get("exit_code", 1),
        "leases": leases,
    }


def _run_uci_show_hosts(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run("uci -j show dhcp.@host[*]", timeout=10.0).to_dict()
            try:
                data = json.loads(raw.get("stdout", "{}"))
            except json.JSONDecodeError:
                data = {}
        else:
            raw = client.run("uci show dhcp", timeout=10.0).to_dict()
            data = _restructure_uci_text(parse_uci_show(raw.get("stdout", "")))
    hosts = data.get("dhcp", {}).get("@host", [])
    return {"raw": raw, "hosts": hosts, "count": len(hosts)}


def _run_uci_show_dnsmasq(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run("uci -j show dhcp.@dnsmasq[0]", timeout=10.0).to_dict()
            try:
                data = json.loads(raw.get("stdout", "{}"))
            except json.JSONDecodeError:
                data = {}
        else:
            raw = client.run("uci show dhcp", timeout=10.0).to_dict()
            data = _restructure_uci_text(parse_uci_show(raw.get("stdout", "")))
    dnsmasq = data.get("dhcp", {}).get("@dnsmasq", [{}])[0]
    return {"raw": raw, "dnsmasq": dnsmasq}


def _run_add_static_lease(
    node_id, auth, ctx, mac: str, ip: str, hostname: str | None
) -> dict:
    if err := validate_mac(mac):
        return {"exit_code": 2, "stderr": err}
    if err := validate_ipv4(ip):
        return {"exit_code": 2, "stderr": err}
    if hostname is not None and (err := validate_hostname(hostname)):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run("uci add dhcp host", timeout=5)
        if r1.exit_code != 0:
            return r1.to_dict()

        section = r1.stdout.strip()
        r2 = client.run(f"uci set dhcp.{section}.mac={mac}", timeout=5)
        if r2.exit_code != 0:
            return r2.to_dict()

        r3 = client.run(f"uci set dhcp.{section}.ip={ip}", timeout=5)
        if r3.exit_code != 0:
            return r3.to_dict()

        if hostname:
            r4 = client.run(f"uci set dhcp.{section}.name={hostname}", timeout=5)
            if r4.exit_code != 0:
                return r4.to_dict()

        r5 = client.run("uci commit dhcp", timeout=5)
        if r5.exit_code != 0:
            return r5.to_dict()

        r6 = client.run("/etc/init.d/dnsmasq restart", timeout=15)
        return r6.to_dict()


def _run_remove_static_lease(node_id, auth, ctx, mac: str) -> dict:
    if err := validate_mac(mac):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run(f"uci show dhcp | grep -i '{mac}' | head -1", timeout=5)
        if r1.exit_code != 0 or not r1.stdout.strip():
            return {"exit_code": 1, "stderr": f"No DHCP host entry found for MAC {mac}"}

        line = r1.stdout.strip()
        match = re.search(r"dhcp\.(\@[^\.]+)\.mac=", line)
        if not match:
            return {
                "exit_code": 1,
                "stderr": f"Could not parse UCI section from: {line}",
            }

        section = match.group(1)
        r2 = client.run(f"uci delete dhcp.{section}", timeout=5)
        if r2.exit_code != 0:
            return r2.to_dict()

        r3 = client.run("uci commit dhcp", timeout=5)
        if r3.exit_code != 0:
            return r3.to_dict()

        r4 = client.run("/etc/init.d/dnsmasq restart", timeout=15)
        return r4.to_dict()


def _run_dhcp_renew(node_id, auth, ctx, iface: str) -> dict:
    if err := validate_iface_name(iface):
        return {"exit_code": 2, "stderr": err}
    with make_client(node_id, auth, ctx) as client:
        return client.run(f"ifdown {iface} && ifup {iface}", timeout=30.0).to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.dhcp_get_leases",
        description="Read the current DHCP lease table from /tmp/dhcp.leases.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def dhcp_get_leases(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_cat_leases, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.dhcp_get_static_assignments",
        description="Read static DHCP host reservations from UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def dhcp_get_static_assignments(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_uci_show_hosts, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.dhcp_get_dns_settings",
        description="Read dnsmasq DNS and DHCP configuration from UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def dhcp_get_dns_settings(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_uci_show_dnsmasq, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.dhcp_add_static_lease",
        description="Add a static DHCP reservation via UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def dhcp_add_static_lease(
        site_id: str,
        node_id: str,
        mac: str,
        ip: str,
        auth: AuthCredential,
        ctx: Context,
        hostname: str | None = None,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_add_static_lease, node_id, auth, ctx, mac, ip, hostname
        )
        return render(raw)

    @mcp.tool(
        name="openwrt.dhcp_remove_static_lease",
        description="Remove a static DHCP reservation by MAC address.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def dhcp_remove_static_lease(
        site_id: str,
        node_id: str,
        mac: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_remove_static_lease, node_id, auth, ctx, mac)
        return render(raw)

    @mcp.tool(
        name="openwrt.dhcp_renew_lease",
        description="Force a DHCP renew on a network interface.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def dhcp_renew_lease(
        site_id: str,
        node_id: str,
        iface: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_dhcp_renew, node_id, auth, ctx, iface)
        return render(raw)
