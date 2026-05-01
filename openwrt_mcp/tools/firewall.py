"""Firewall tools for the OpenWrt MCP server."""

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
)

_VALID_TARGETS = frozenset({"ACCEPT", "DROP", "REJECT"})
_VALID_PROTOS = frozenset({"tcp", "udp", "all"})


def _run_firewall_show(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run("uci -j show firewall", timeout=10.0).to_dict()
            try:
                data = json.loads(raw.get("stdout", "{}"))
            except json.JSONDecodeError:
                data = {}
        else:
            raw = client.run("uci show firewall", timeout=10.0).to_dict()
            data = _restructure_uci_text(parse_uci_show(raw.get("stdout", "")))
    try:
        rules = data.get("firewall", {}).get("@rule", [])
        active = [r for r in rules if r.get("enabled", "1") != "0"]
        return {"raw": raw, "rules": active, "count": len(active)}
    except (KeyError, TypeError):
        return {"raw": raw, "rules": [], "count": 0}


def _run_firewall_zones(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run("uci -j show firewall.@zone[*]", timeout=10.0).to_dict()
            try:
                data = json.loads(raw.get("stdout", "{}"))
            except json.JSONDecodeError:
                data = {}
        else:
            raw = client.run("uci show firewall", timeout=10.0).to_dict()
            data = _restructure_uci_text(parse_uci_show(raw.get("stdout", "")))
    try:
        section = data.get("firewall", {})
        zones = section.get("@zone", [])
        return {"raw": raw, "zones": zones, "count": len(zones)}
    except (AttributeError, TypeError):
        return {"raw": raw, "zones": [], "count": 0}


def _run_firewall_add_rule(
    node_id,
    auth,
    ctx,
    src: str,
    dest: str,
    target: str,
    proto: str,
    src_port: str | None,
    dest_port: str | None,
) -> dict:
    if target not in _VALID_TARGETS:
        return {"exit_code": 2, "stderr": f"Invalid target: {target}"}
    if proto not in _VALID_PROTOS:
        return {"exit_code": 2, "stderr": f"Invalid proto: {proto}"}

    with make_client(node_id, auth, ctx) as client:
        r1 = client.run("uci add firewall rule", timeout=5)
        if r1.exit_code != 0:
            return r1.to_dict()

        section = r1.stdout.strip()

        def uci_set(path, val):
            return client.run(f"uci set firewall.{section}.{path}={val}", timeout=5)

        r2 = uci_set("src", src)
        if r2.exit_code != 0:
            return r2.to_dict()
        r3 = uci_set("dest", dest)
        if r3.exit_code != 0:
            return r3.to_dict()
        r4 = uci_set("target", target)
        if r4.exit_code != 0:
            return r4.to_dict()
        r5 = uci_set("proto", proto)
        if r5.exit_code != 0:
            return r5.to_dict()
        if src_port:
            r6 = uci_set("src_port", src_port)
            if r6.exit_code != 0:
                return r6.to_dict()
        if dest_port:
            r7 = uci_set("dest_port", dest_port)
            if r7.exit_code != 0:
                return r7.to_dict()

        r8 = client.run("uci commit firewall", timeout=5)
        if r8.exit_code != 0:
            return r8.to_dict()
        r9 = client.run("/etc/init.d/firewall reload", timeout=30)
        return r9.to_dict()


_RULE_LINE_RE = re.compile(
    r"firewall\.(@rule\[\d+\])\.(\w+)=(.*)$",
)


def _find_matching_rules(
    raw_stdout: str, src: str, dest: str, target: str
) -> list[str]:
    """Parse `uci show firewall`-style output, return UCI sections where
    ALL of src / dest / target match exactly (not OR; not substring).
    """
    rules: dict[str, dict[str, str]] = {}
    for raw_line in raw_stdout.strip().splitlines():
        m = _RULE_LINE_RE.search(raw_line)
        if not m:
            continue
        section, field, value = m.groups()
        rules.setdefault(section, {})[field] = value.strip().strip("'\"")
    return [
        section
        for section, fields in rules.items()
        if fields.get("src") == src
        and fields.get("dest") == dest
        and fields.get("target") == target
    ]


def _run_firewall_remove_rule(
    node_id,
    auth,
    ctx,
    src: str,
    dest: str,
    target: str,
) -> dict:
    with make_client(node_id, auth, ctx) as client:
        r1 = client.run("uci show firewall", timeout=10)
        if r1.exit_code != 0:
            return r1.to_dict()
        matching = _find_matching_rules(r1.stdout, src, dest, target)
        if not matching:
            return {
                "exit_code": 1,
                "stderr": (
                    f"No firewall rule found matching ALL: "
                    f"src={src} dest={dest} target={target}"
                ),
            }
        if len(matching) > 1:
            return {
                "exit_code": 1,
                "stderr": (
                    f"Ambiguous: {len(matching)} rules match ALL of "
                    f"src={src} dest={dest} target={target} "
                    f"({', '.join(matching)}). Refine criteria or remove "
                    f"manually via SSH."
                ),
            }
        section = matching[0]
        r2 = client.run(f"uci delete firewall.{section}", timeout=5)
        if r2.exit_code != 0:
            return r2.to_dict()
        r3 = client.run("uci commit firewall", timeout=5)
        if r3.exit_code != 0:
            return r3.to_dict()
        r4 = client.run("/etc/init.d/firewall reload", timeout=30)
        return r4.to_dict()


def _run_firewall_reload(node_id, auth, ctx) -> dict:
    with make_client(node_id, auth, ctx) as client:
        return client.run("/etc/init.d/firewall reload", timeout=30.0).to_dict()


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.firewall_get_rules",
        description="Read active firewall rules from UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def firewall_get_rules(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_firewall_show, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.firewall_get_zones",
        description="Read firewall zone definitions from UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def firewall_get_zones(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_firewall_zones, node_id, auth, ctx)
        return render(raw)

    @mcp.tool(
        name="openwrt.firewall_add_rule",
        description="Add a firewall rule via UCI.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def firewall_add_rule(
        site_id: str,
        node_id: str,
        src: str,
        dest: str,
        target: str,
        auth: AuthCredential,
        ctx: Context,
        proto: str = "all",
        src_port: str | None = None,
        dest_port: str | None = None,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_firewall_add_rule,
            node_id,
            auth,
            ctx,
            src,
            dest,
            target,
            proto,
            src_port,
            dest_port,
        )
        return render(raw)

    @mcp.tool(
        name="openwrt.firewall_remove_rule",
        description="Remove a firewall rule by matching src/dest/target.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def firewall_remove_rule(
        site_id: str,
        node_id: str,
        src: str,
        dest: str,
        target: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(
            _run_firewall_remove_rule,
            node_id,
            auth,
            ctx,
            src,
            dest,
            target,
        )
        return render(raw)

    @mcp.tool(
        name="openwrt.firewall_reload",
        description="Reload the firewall configuration.",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
        meta={},
    )
    async def firewall_reload(
        site_id: str,
        node_id: str,
        auth: AuthCredential,
        ctx: Context,
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_firewall_reload, node_id, auth, ctx)
        return render(raw)
