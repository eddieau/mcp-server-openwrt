"""Helpers shared across every OpenWrt tool module."""

from __future__ import annotations

import os
import re
from typing import Any

from mcp.server.fastmcp import Context
from mcp.types import CallToolResult

from openwrt_mcp.client import OpenWrtClient
from openwrt_mcp.schemas import AuthCredential

_UCI_SECTION = re.compile(r"^@([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]$")


# -------------------------------------------------------------------------
# Input validation — shell-injection hardening for write tools
# -------------------------------------------------------------------------

_IFACE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,30}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_IPV4_RE = re.compile(r"^[0-9.]{7,15}$")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")
_SSID_RE = re.compile(r"^[a-zA-Z0-9 ._\-]{1,32}$")
_WPA_PSK_SHELL_META = set("$`;|&\"'<>()\\\n\r\t ")


def validate_iface_name(value: str, *, field: str = "iface") -> str | None:
    """Return error message if invalid, else None."""
    if not _IFACE_NAME_RE.match(value):
        return f"Invalid {field} name: {value!r} (alnum + . _ - only, max 31 chars)"
    return None


def validate_mac(value: str) -> str | None:
    if not _MAC_RE.match(value):
        return f"Invalid MAC address: {value!r}"
    return None


def validate_ipv4(value: str) -> str | None:
    import ipaddress

    if not _IPV4_RE.match(value):
        return f"Invalid IPv4 format: {value!r}"
    try:
        ipaddress.IPv4Address(value)
    except ValueError as e:
        return f"Invalid IPv4 address: {value!r} ({e})"
    return None


def validate_hostname(value: str) -> str | None:
    if not _HOSTNAME_RE.match(value):
        return f"Invalid hostname: {value!r}"
    return None


def validate_ssid(value: str) -> str | None:
    if not _SSID_RE.match(value):
        return (
            f"Invalid SSID: {value!r} (1-32 chars; alnum + space . _ - only "
            f"in this version — set unicode SSIDs via local UCI)"
        )
    return None


def validate_wpa_psk(value: str) -> str | None:
    if not isinstance(value, str):
        return "WPA passphrase must be a string"
    if not (8 <= len(value) <= 63):
        return f"WPA passphrase must be 8-63 chars; got {len(value)}"
    bad = [c for c in value if c in _WPA_PSK_SHELL_META]
    if bad:
        return (
            f"WPA passphrase contains characters not allowed via this tool "
            f"({sorted(set(bad))!r}); set via local UCI for special chars"
        )
    return None


def _resolve_host_port(node_id: str, ctx: Context) -> tuple[str, int]:
    """Resolve host:port from lifespan context node_url_map or env vars."""
    try:
        resolved = ctx.request_context.lifespan_context.get("node_url_map", {})
    except (AttributeError, LookupError):
        resolved = {}
    if node_id in resolved:
        spec = resolved[node_id]
        if ":" in spec:
            host, port_s = spec.rsplit(":", 1)
            try:
                return host, int(port_s)
            except ValueError:
                pass
        return spec, int(os.environ.get("OPENWRT_PORT", "22"))
    host = os.environ.get("OPENWRT_HOST")
    if not host:
        raise ValueError(f"Cannot resolve node_id={node_id!r} — no OPENWRT_HOST set")
    return host, int(os.environ.get("OPENWRT_PORT", "22"))


def make_client(node_id: str, auth: AuthCredential, ctx: Context) -> OpenWrtClient:
    """Per-call client construction. Tools use a `with` block so
    Paramiko's blocking session closes cleanly even on exception."""
    host, port = _resolve_host_port(node_id, ctx)
    return OpenWrtClient(
        host=host,
        user=auth.username,
        password=auth.password,
        port=port,
        connect_timeout=float(os.environ.get("OPENWRT_CONNECT_TIMEOUT", "10")),
        command_timeout=float(os.environ.get("OPENWRT_COMMAND_TIMEOUT", "30")),
    )


# -------------------------------------------------------------------------
# UCI -j compatibility
# -------------------------------------------------------------------------

# Per-host cache so multiple OpenWrt versions in one fleet don't share a
# wrong cache entry. Keyed by the SSH host string.
_UCI_JSON_CACHE: dict[str, bool] = {}


def _detect_uci_json_support(client: OpenWrtClient) -> bool:
    """Probe per-host: does this OpenWrt accept `uci -j`?"""
    host = getattr(client, "_host", None) or ""
    cached = _UCI_JSON_CACHE.get(host)
    if cached is not None:
        return cached
    probe = client.run("uci -j show system 2>&1 | head -c 200", timeout=5)
    supported = probe.exit_code == 0 and "unrecognized option: j" not in (
        probe.stdout or ""
    )
    _UCI_JSON_CACHE[host] = supported
    return supported


def parse_uci_show(stdout: str) -> dict[str, Any]:
    """Parse text-format `uci show` output into nested dict."""
    out: dict[str, Any] = {}
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("'\"")
        parts = key.split(".")
        d = out
        for p in parts[:-1]:
            existing = d.get(p)
            if isinstance(existing, dict):
                d = existing
            else:
                new_dict: dict[str, Any] = {}
                if isinstance(existing, str):
                    new_dict[".type"] = existing
                d[p] = new_dict
                d = new_dict
        d[parts[-1]] = value
    return out


def _restructure_uci_text(data: dict[str, Any]) -> dict[str, Any]:
    """Convert text-format UCI output into array-valued sections."""
    for config_name, config_data in list(data.items()):
        if not isinstance(config_data, dict):
            continue
        by_section: dict[str, list[dict[str, Any]]] = {}
        section_keys = [k for k in config_data if k.startswith("@")]
        for key in section_keys:
            m = _UCI_SECTION.match(key)
            if not m:
                continue
            section_name = m.group(1)
            index = int(m.group(2))
            entry = config_data[key]
            if section_name not in by_section:
                by_section[section_name] = []
            while len(by_section[section_name]) <= index:
                by_section[section_name].append({})
            by_section[section_name][index].update(entry)
        for key in section_keys:
            del config_data[key]
        for section_name, entries in by_section.items():
            config_data[f"@{section_name}"] = entries
    return data


# -------------------------------------------------------------------------
# Render
# -------------------------------------------------------------------------


def render(raw: Any) -> CallToolResult:
    """Wrap a native OpenWrt response as a CallToolResult.

    R3-equivalent (mirror of adguard-mcp/_common.py post-R3):
    tools return native shape directly. Canonical mapping at the
    """
    if not isinstance(raw, dict):
        structured: dict[str, Any] = {"data": raw}
    else:
        structured = raw
    return CallToolResult(
        content=[],
        structuredContent=structured,
    )
