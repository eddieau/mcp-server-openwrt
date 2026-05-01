"""Input models for the OpenWrt MCP server.

The adapter gateway resolves `credential_ref` → AuthCredential before the
call; the server itself never sees the ref. We override repr/str so a
stray log statement can't leak the password.

Mirrors the AdGuard adapter's AuthCredential. OpenWrt SSH auth is a
straight username/password pair (key-auth is out of scope for v0 —
see client.py `look_for_keys=False` rationale).
"""

from __future__ import annotations

from pydantic import BaseModel


class AuthCredential(BaseModel):
    username: str
    password: str

    def __repr__(self) -> str:
        return f"AuthCredential(username={self.username!r}, password=***)"

    def __str__(self) -> str:
        return self.__repr__()
