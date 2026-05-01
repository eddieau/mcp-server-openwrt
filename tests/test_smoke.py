"""Smoke tests for the OpenWrt MCP server package."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent


class TestSyntaxClean:
    """All .py files must parse without SyntaxError."""

    PY_FILES = [
        "openwrt_mcp/__init__.py",
        "openwrt_mcp/main.py",
        "openwrt_mcp/client.py",
        "openwrt_mcp/schemas.py",
        "openwrt_mcp/server.py",
        "openwrt_mcp/tools/__init__.py",
        "openwrt_mcp/tools/_common.py",
        "openwrt_mcp/tools/dhcp.py",
        "openwrt_mcp/tools/firewall.py",
        "openwrt_mcp/tools/network.py",
        "openwrt_mcp/tools/system.py",
        "openwrt_mcp/tools/opkg.py",
        "openwrt_mcp/tools/service.py",
        "openwrt_mcp/tools/uci.py",
        "openwrt_mcp/tools/wireless.py",
    ]

    @pytest.mark.parametrize("rel_path", PY_FILES)
    def test_file_parses(self, rel_path: str) -> None:
        file_path = ROOT / rel_path
        assert file_path.exists(), f"{rel_path} not found"
        source = file_path.read_text(encoding="utf-8")
        ast.parse(source)


class TestToolCount:
    """manifest.yaml declares exactly 37 tools."""

    def test_tool_count(self) -> None:
        import yaml

        manifest = yaml.safe_load((ROOT / "manifest.yaml").read_text())
        tools = manifest.get("tools", [])
        assert len(tools) == 37, f"Expected 37 tools, got {len(tools)}"

    @pytest.mark.parametrize(
        "domain,expected",
        [
            ("dhcp", 6),
            ("firewall", 5),
            ("network", 9),
            ("system", 5),
            ("opkg", 3),
            ("service", 1),
            ("uci", 2),
            ("wireless", 6),
        ],
    )
    def test_domain_tool_counts(self, domain: str, expected: int) -> None:
        import yaml

        manifest = yaml.safe_load((ROOT / "manifest.yaml").read_text())
        tool_names = [t["name"] for t in manifest.get("tools", [])]
        # network domain: openwrt.network_* + check_wan/check_gateway + restart_wan
        if domain == "network":
            domain_tools = [
                n
                for n in tool_names
                if n.startswith("openwrt.network_")
                or n
                in ("openwrt.check_wan", "openwrt.check_gateway", "openwrt.restart_wan")
            ]
        # system domain: openwrt.system_* + reboot_router
        elif domain == "system":
            domain_tools = [
                n
                for n in tool_names
                if n.startswith("openwrt.system_") or n == "openwrt.reboot_router"
            ]
        # wireless domain: includes openwrt.wireless_* + openwrt.check_wifi
        elif domain == "wireless":
            domain_tools = [
                n
                for n in tool_names
                if n.startswith("openwrt.wireless_") or n == "openwrt.check_wifi"
            ]
        else:
            domain_tools = [n for n in tool_names if n.startswith(f"openwrt.{domain}_")]
        assert len(domain_tools) == expected, (
            f"{domain}: expected {expected}, got {len(domain_tools)} — {domain_tools}"
        )


class TestDualModeTransport:
    """openwrt_mcp/main.py reads MCP_TRANSPORT env var and defaults to stdio."""

    def test_main_uses_mcp_transport_env_var(self) -> None:
        main_text = (ROOT / "openwrt_mcp" / "main.py").read_text()
        assert "MCP_TRANSPORT" in main_text
        assert (
            'os.environ.get("MCP_TRANSPORT"' in main_text
            or "os.environ.get('MCP_TRANSPORT'" in main_text
        )

    def test_main_defaults_to_stdio(self) -> None:
        main_text = (ROOT / "openwrt_mcp" / "main.py").read_text()
        assert "stdlib" not in main_text  # "stdio" is the env value
        assert '"stdio"' in main_text or "'stdio'" in main_text
