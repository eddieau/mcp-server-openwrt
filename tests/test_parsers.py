"""Pure-function unit tests for parsers + validators.

These tests don't touch SSH / FastMCP — they exercise the data
transformation primitives. Run before each push to catch regressions
(parser drift, validator gaps).
"""

from __future__ import annotations

import pytest

from openwrt_mcp.schemas import AuthCredential
from openwrt_mcp.tools._common import (
    parse_uci_show,
    validate_hostname,
    validate_iface_name,
    validate_ipv4,
    validate_mac,
    validate_ssid,
    validate_wpa_psk,
)
from openwrt_mcp.tools.dhcp import _parse_leases
from openwrt_mcp.tools.firewall import _find_matching_rules
from openwrt_mcp.tools.network import _parse_arp_lines


# ─── DHCP lease parser ─────────────────────────────────────────────────


class TestLeaseParser:
    def test_normal_line(self) -> None:
        text = "1234567890 aa:bb:cc:dd:ee:ff 192.168.1.50 my-host abc-id"
        leases = _parse_leases(text)
        assert len(leases) == 1
        assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert leases[0]["ip"] == "192.168.1.50"
        assert leases[0]["hostname"] == "my-host"

    def test_no_hostname(self) -> None:
        text = "1234567890 aa:bb:cc:dd:ee:ff 192.168.1.50 * abc-id"
        leases = _parse_leases(text)
        assert len(leases) == 1
        assert leases[0]["hostname"] == "*"

    def test_uppercase_mac_normalised(self) -> None:
        text = "1234567890 AA:BB:CC:DD:EE:FF 192.168.1.50 host id"
        leases = _parse_leases(text)
        assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_empty_input(self) -> None:
        assert _parse_leases("") == []
        assert _parse_leases("\n\n") == []

    def test_multiple_lines(self) -> None:
        text = (
            "1 aa:bb:cc:dd:ee:01 192.168.1.10 host-a id-a\n"
            "2 aa:bb:cc:dd:ee:02 192.168.1.11 host-b id-b\n"
        )
        leases = _parse_leases(text)
        assert len(leases) == 2
        assert leases[0]["ip"] == "192.168.1.10"
        assert leases[1]["ip"] == "192.168.1.11"


# ─── ARP parser ────────────────────────────────────────────────────────


class TestArpParser:
    def test_normal_entry(self) -> None:
        text = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        entries = _parse_arp_lines(text)
        assert len(entries) == 1
        assert entries[0] == {
            "ip": "192.168.1.10",
            "iface": "br-lan",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

    def test_skips_failed_neighbours(self) -> None:
        text = "192.168.1.99 dev br-lan FAILED"
        # No lladdr → doesn't match _ARP_RE → skipped
        assert _parse_arp_lines(text) == []

    def test_empty_input(self) -> None:
        assert _parse_arp_lines("") == []


# ─── UCI text-format parser ────────────────────────────────────────────


class TestUciShowParser:
    def test_simple_kv(self) -> None:
        text = "network.lan.ipaddr=192.168.1.1\nnetwork.lan.netmask=255.255.255.0"
        parsed = parse_uci_show(text)
        assert parsed["network"]["lan"]["ipaddr"] == "192.168.1.1"
        assert parsed["network"]["lan"]["netmask"] == "255.255.255.0"

    def test_quoted_values_unwrapped(self) -> None:
        text = "system.@system[0].hostname='OpenWrt'"
        parsed = parse_uci_show(text)
        assert "OpenWrt" in str(parsed)

    def test_empty_input(self) -> None:
        assert parse_uci_show("") == {}

    def test_skips_lines_without_equals(self) -> None:
        text = "junk line\nnetwork.lan.ipaddr=10.0.0.1"
        parsed = parse_uci_show(text)
        assert parsed["network"]["lan"]["ipaddr"] == "10.0.0.1"


# ─── Firewall rule matcher ─────────────────────────────────────────────


class TestFindMatchingRules:
    """Regression tests for the OR-vs-AND bug in firewall_remove_rule."""

    SAMPLE_OUTPUT = """firewall.@rule[0]=rule
firewall.@rule[0].name='Allow-DHCP-Renew'
firewall.@rule[0].src='wan'
firewall.@rule[0].dest='lan'
firewall.@rule[0].target='ACCEPT'
firewall.@rule[1]=rule
firewall.@rule[1].name='Block-Telnet'
firewall.@rule[1].src='lan'
firewall.@rule[1].dest='wan'
firewall.@rule[1].target='DROP'
firewall.@rule[2]=rule
firewall.@rule[2].src='wan'
firewall.@rule[2].dest='wan'
firewall.@rule[2].target='ACCEPT'
"""

    def test_matches_only_when_all_three_match(self) -> None:
        result = _find_matching_rules(
            self.SAMPLE_OUTPUT, src="lan", dest="wan", target="DROP"
        )
        assert result == ["@rule[1]"]

    def test_no_match_returns_empty(self) -> None:
        result = _find_matching_rules(
            self.SAMPLE_OUTPUT, src="nope", dest="zilch", target="ACCEPT"
        )
        assert result == []

    def test_does_not_match_partial_only(self) -> None:
        # src=lan only matches @rule[1]; dest=lan only matches @rule[0];
        # neither has src=lan AND dest=lan AND target=ACCEPT — must be empty.
        result = _find_matching_rules(
            self.SAMPLE_OUTPUT, src="lan", dest="lan", target="ACCEPT"
        )
        assert result == []

    def test_unique_match_returns_section(self) -> None:
        result = _find_matching_rules(
            self.SAMPLE_OUTPUT, src="wan", dest="lan", target="ACCEPT"
        )
        assert result == ["@rule[0]"]


# ─── Validators ────────────────────────────────────────────────────────


class TestValidators:
    @pytest.mark.parametrize(
        "value,expected_valid",
        [
            ("aa:bb:cc:dd:ee:ff", True),
            ("AA:BB:CC:DD:EE:FF", True),
            ("aa-bb-cc-dd-ee-ff", True),
            ("aa:bb:cc:dd:ee", False),
            ("not-a-mac", False),
            ("aa:bb:cc:dd:ee:ff;rm -rf /", False),
        ],
    )
    def test_validate_mac(self, value: str, expected_valid: bool) -> None:
        result = validate_mac(value)
        assert (result is None) == expected_valid

    @pytest.mark.parametrize(
        "value,expected_valid",
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("256.0.0.1", False),
            ("not-an-ip", False),
            ("1.1.1.1; rm -rf /", False),
            ("192.168.1.1$(whoami)", False),
        ],
    )
    def test_validate_ipv4(self, value: str, expected_valid: bool) -> None:
        assert (validate_ipv4(value) is None) == expected_valid

    @pytest.mark.parametrize(
        "value,expected_valid",
        [
            ("eth0", True),
            ("wan", True),
            ("br-lan", True),
            ("eth0.100", True),
            ("eth0; rm -rf /", False),
            ("eth0$VAR", False),
            ("eth0 ", False),
            ("", False),
        ],
    )
    def test_validate_iface_name(self, value: str, expected_valid: bool) -> None:
        assert (validate_iface_name(value) is None) == expected_valid

    def test_validate_wpa_psk_too_short(self) -> None:
        assert validate_wpa_psk("short") is not None

    def test_validate_wpa_psk_valid(self) -> None:
        assert validate_wpa_psk("MyValidPassword123") is None

    def test_validate_wpa_psk_rejects_shell_meta(self) -> None:
        for bad in ["pass$word", "pass;word", "pass`word", "pass|word", "pass'word"]:
            assert validate_wpa_psk(bad) is not None, f"{bad!r} should be rejected"

    @pytest.mark.parametrize(
        "value,expected_valid",
        [
            ("MyHomeWiFi", True),
            ("Home_Network-2.4G", True),
            ("Guest", True),
            ("", False),
            ("a" * 33, False),
            ("ssid; rm -rf /", False),
        ],
    )
    def test_validate_ssid(self, value: str, expected_valid: bool) -> None:
        assert (validate_ssid(value) is None) == expected_valid

    def test_validate_hostname_normal(self) -> None:
        assert validate_hostname("my-host") is None
        assert validate_hostname("printer.local") is None
        assert validate_hostname("host_with_underscore") is None

    def test_validate_hostname_rejects_meta(self) -> None:
        assert validate_hostname("host;rm") is not None
        assert validate_hostname("host$(whoami)") is not None


# ─── AuthCredential password masking ──────────────────────────────────


class TestAuthCredentialMasking:
    def test_repr_masks_password(self) -> None:
        cred = AuthCredential(username="admin", password="super-secret-123")
        rep = repr(cred)
        assert "super-secret-123" not in rep
        assert "admin" in rep
        assert "***" in rep

    def test_str_also_masks(self) -> None:
        cred = AuthCredential(username="admin", password="super-secret-123")
        assert "super-secret-123" not in str(cred)
