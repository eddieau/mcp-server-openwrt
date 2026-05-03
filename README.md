# mcp-server-openwrt

MIT-licensed standalone MCP server for OpenWrt routers. Provides read probes and write actions over SSH.

## Two Modes

### Standalone / Claude Desktop

Env-based auth (no per-call credential injection):

```bash
export OPENWRT_HOST=192.168.1.1
export OPENWRT_USER=root
export OPENWRT_PASS=your_password
export MCP_TRANSPORT=streamable-http
export MCP_HOST=0.0.0.0
export MCP_PORT=8002

pip install -r requirements.txt
python -m openwrt_mcp.main
```

### Embedded mode (host project injects auth per call)

When this MCP server is embedded as a submodule in a larger project that
manages credentials per request, host code passes an `auth` argument
on each tool call (`{username, password}`) instead of relying on env
vars:

```python
# auth injected per-call by the host — not from env vars
result = await session.call_tool(
    name="openwrt.check_wan",
    arguments={
        "site_id": "site-home-lab",
        "node_id": "openwrt-main",
        "auth": {"username": "...", "password": "..."}
    }
)
```

Transport mode is `streamable-http` when running inside a host's
container compose.

### `site_id` parameter

Every tool accepts a `site_id: str` argument as part of its
signature. This MCP server itself does NOT use `site_id` — only
`node_id` + `auth` are read by the SSH client. `site_id` is
**reserved for future per-site authorisation routing** in
embedding host projects (e.g. an MSP gateway that fans tool calls
across many customer sites). Today, callers may pass any string.
Do NOT assume `site_id` is being checked or enforced inside this
server.

## Transport Modes

| Mode | Env vars needed | Use case |
|---|---|---|
| `stdio` | None | Claude Desktop, direct CLI |
| `streamable-http` | `MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=8002` | Containerised / host-gateway deploys |

```bash
# stdio (default)
python -m openwrt_mcp.main

# streamable-http
MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=8002 python -m openwrt_mcp.main
```

## Tools (37 across 7 domains)

| Domain | Tools |
|---|---|
| **dhcp** | `dhcp_get_leases`, `dhcp_get_static_assignments`, `dhcp_add_static_lease`, `dhcp_remove_static_lease`, `dhcp_get_dns_settings`, `dhcp_renew_lease` |
| **firewall** | `firewall_get_rules`, `firewall_get_zones`, `firewall_add_rule`, `firewall_remove_rule`, `firewall_reload` |
| **network** | `network_get_interfaces`, `network_get_routes`, `network_get_arp_table`, `network_set_interface_ip`, `network_restart_interface`, `network_get_dns_resolvers`, `check_wan`, `check_gateway`, `restart_wan` |
| **opkg** | `opkg_list`, `opkg_install`, `opkg_remove` |
| **service** | `service_action` |
| **system** | `reboot_router`, `system_get_uptime`, `system_get_load`, `system_get_memory`, `system_get_processes` |
| **uci** | `uci_show`, `uci_get` |
| **wireless** | `check_wifi`, `wireless_get_clients`, `wireless_get_signal_strength`, `wireless_set_ssid`, `wireless_restart_radio`, `wireless_set_password` |

## Quick Start (Standalone)

```bash
git clone https://github.com/eddieau/mcp-server-openwrt.git
cd mcp-server-openwrt

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Smoke test (needs a real router)
export OPENWRT_HOST=192.168.1.1
export OPENWRT_USER=root
export OPENWRT_PASS=your_password

MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8002 python -m openwrt_mcp.main &
sleep 2
curl -s http://127.0.0.1:8002/mcp -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  -H "Accept: text/event-stream" | head -5
```

## Docker

```bash
docker build -t mcp-server-openwrt .
docker run --rm -e MCP_TRANSPORT=streamable-http -e MCP_HOST=0.0.0.0 -e MCP_PORT=8002 \
  -e OPENWRT_HOST=192.168.1.1 -e OPENWRT_USER=root -e OPENWRT_PASS=pass \
  -p 8002:8002 mcp-server-openwrt
```

## Architecture

- **Auth**: Pydantic `AuthCredential` for per-call credentials (embedded) or env vars (standalone)
- **Transport**: FastMCP with dual-mode (`stdio` / `streamable-http`) via `MCP_TRANSPORT` env var
- **SSH**: Paramiko synchronous client run on a thread pool via `asyncio.to_thread`
- **Canonical mapping**: Done by downstream consumers — this MCP server emits native OpenWrt shapes only; no `structuredContent.checks[]` injection

## License

MIT
