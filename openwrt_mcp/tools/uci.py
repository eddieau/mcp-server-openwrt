"""UCI (Unified Configuration Interface) tools for the OpenWrt MCP server."""

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

_UCI_CONFIGS = frozenset(
    {
        "network",
        "firewall",
        "wireless",
        "dhcp",
        "system",
        "uhttpd",
        "dropbear",
        "qos",
        "mwan3",
    }
)

_UCI_PATH_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9_-]*(?:\.(?:[a-zA-Z0-9_-]+|@[a-zA-Z0-9_-]+\[\d+\]))"
    r"(?:\.[a-zA-Z0-9_-]+)?\Z"
)


def _run_uci_show(node_id, auth, ctx, config: str) -> dict:
    if config not in _UCI_CONFIGS:
        return {"exit_code": 2, "stderr": f"Unknown UCI config '{config}'"}
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run(f"uci -j show {config}", timeout=10.0).to_dict()
            try:
                data = json.loads(raw.get("stdout", "{}"))
            except json.JSONDecodeError:
                data = {}
        else:
            raw = client.run(f"uci show {config}", timeout=10.0).to_dict()
            data = _restructure_uci_text(parse_uci_show(raw.get("stdout", "")))
        return {"raw": raw, "data": data, "config": config}


def _run_uci_get(node_id, auth, ctx, path: str) -> dict:
    if not _UCI_PATH_RE.match(path):
        return {"exit_code": 2, "stderr": f"Invalid UCI path format: {path}"}
    config = path.split(".", 1)[0]
    if config not in _UCI_CONFIGS:
        return {"exit_code": 2, "stderr": f"Unknown UCI config '{config}'"}
    with make_client(node_id, auth, ctx) as client:
        if _detect_uci_json_support(client):
            raw = client.run(f"uci -j get {path}", timeout=10.0).to_dict()
            try:
                value = json.loads(raw.get("stdout", "null"))
            except json.JSONDecodeError:
                value = None
        else:
            raw = client.run(f"uci get {path}", timeout=10.0).to_dict()
            value = raw.get("stdout", "").strip().strip("'\"")
        return {
            "raw": raw,
            "path": path,
            "value": value,
            "exit_code": raw.get("exit_code", 0),
        }


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="openwrt.uci_show",
        description="Dump the full UCI configuration tree for a config section via `uci -j show <config>`.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def uci_show(
        site_id: str, node_id: str, config: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_uci_show, node_id, auth, ctx, config)
        return render(raw)

    @mcp.tool(
        name="openwrt.uci_get",
        description="Read a single UCI value by dot-separated path (e.g. network.lan.ipaddr).",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
        meta={},
    )
    async def uci_get(
        site_id: str, node_id: str, path: str, auth: AuthCredential, ctx: Context
    ) -> CallToolResult:
        raw = await asyncio.to_thread(_run_uci_get, node_id, auth, ctx, path)
        return render(raw)
