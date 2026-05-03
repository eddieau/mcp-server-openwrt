"""Thin SSH client around Paramiko.

Designed for the adapter use-case: open a connection, run a few commands,
close. No connection pooling — the overhead of a fresh SSH handshake is
negligible compared to the surface area that a long-lived, shared channel
would add (stuck channels, stale auth, concurrency bugs).

The client is synchronous (Paramiko is blocking). The adapter offloads
`run()` onto a worker thread via `asyncio.to_thread` so the FastMCP event
loop never blocks on SSH I/O.

Ported verbatim from the legacy REST adapter at apps/adapters/openwrt/.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from typing import Any

import paramiko

# Default timeouts — override via OpenWrtClient kwargs.
DEFAULT_CONNECT_TIMEOUT_S = 10.0
DEFAULT_COMMAND_TIMEOUT_S = 30.0

# Optional path to an SSH known_hosts file. When set, the client pins
# the router's host key against this file and rejects unknown hosts —
# the secure default for production / multi-tenant deployments. When
# unset, falls back to AutoAddPolicy (TOFU — fine for homelab /
# appliance-style targets behind a controlled network).
ENV_KNOWN_HOSTS = "OPENWRT_KNOWN_HOSTS"


class SSHCommandError(RuntimeError):
    """Raised when a command exceeds its timeout or the channel dies."""


def _redact_command(command: str, *, head_chars: int = 40) -> str:
    """Truncate a command for safe inclusion in error messages.

    UCI / wireless commands frequently embed credentials in arguments
    (e.g. `uci set wireless.@wifi-iface[0].key=<password>`). The first
    ~40 chars carry the verb + path which are the useful diagnostic
    bits; arguments past that may contain caller-supplied values that
    should not surface in stack traces or aggregated logs.
    """
    if len(command) <= head_chars:
        return command
    return f"{command[:head_chars]}…(truncated)"


@dataclass(slots=True)
class CommandOutcome:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": self.duration_s,
        }


class OpenWrtClient:
    """SSH → OpenWrt router. Use as a context manager to guarantee cleanup."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        *,
        port: int = 22,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_S,
        command_timeout: float = DEFAULT_COMMAND_TIMEOUT_S,
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._port = port
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout
        self._client: paramiko.SSHClient | None = None

    # --- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "OpenWrtClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        client = paramiko.SSHClient()
        # Host-key policy:
        #   - OPENWRT_KNOWN_HOSTS=<path> → pin against that file +
        #     RejectPolicy on miss (secure default for production /
        #     multi-tenant). Operator generates the file via
        #     `ssh-keyscan -H <router> >> known_hosts` once at
        #     onboarding and re-uses across deploys.
        #   - unset → AutoAddPolicy (TOFU). Fine for appliance-style
        #     targets behind a controlled network (homelab, branch
        #     LAN). Documented trade-off, not a default-deny.
        known_hosts = os.environ.get(ENV_KNOWN_HOSTS)
        if known_hosts:
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self._host,
            port=self._port,
            username=self._user,
            password=self._password,
            timeout=self._connect_timeout,
            banner_timeout=self._connect_timeout,
            auth_timeout=self._connect_timeout,
            allow_agent=False,  # avoid picking up an ssh-agent by accident
            look_for_keys=False,  # password-only by spec
        )
        self._client = client

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    # --- commands ----------------------------------------------------------

    def run(self, command: str, *, timeout: float | None = None) -> CommandOutcome:
        """Execute a single command, capture stdout/stderr/exit_code.

        Non-zero exit codes are NOT raised — they are returned so the caller
        can decide. Timeout / channel failure DO raise `SSHCommandError`.
        """
        if self._client is None:
            raise SSHCommandError("SSH client is not connected")

        effective_timeout = timeout if timeout is not None else self._command_timeout
        started = time.perf_counter()
        try:
            _, stdout, stderr = self._client.exec_command(
                command, timeout=effective_timeout
            )
            # settimeout on the channel covers recv() calls below.
            stdout.channel.settimeout(effective_timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            exit_code = stdout.channel.recv_exit_status()
        except socket.timeout as e:
            raise SSHCommandError(
                f"command timed out after {effective_timeout}s: "
                f"{_redact_command(command)}"
            ) from e
        except paramiko.SSHException as e:
            raise SSHCommandError(
                f"SSH error running {_redact_command(command)!r}: {e}"
            ) from e

        duration = time.perf_counter() - started
        return CommandOutcome(
            command=command,
            exit_code=exit_code,
            stdout=out,
            stderr=err,
            duration_s=round(duration, 3),
        )

    def fire_and_forget(self, command: str) -> None:
        """Dispatch a command that will terminate the SSH session (e.g. reboot).

        We don't wait for exit status — the router is going down, so any
        disconnect / read error is expected, not a failure mode.
        """
        if self._client is None:
            raise SSHCommandError("SSH client is not connected")
        try:
            self._client.exec_command(command, timeout=5)
        except (paramiko.SSHException, socket.timeout, OSError):
            # Expected when the command tears the session down mid-call.
            pass
