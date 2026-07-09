"""Temporary credentials for the 1-2 Playwright evidence replay.

TODO: Replace these values with accounts supplied by the diagnosis workflow
after the replay pipeline has been verified.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReplayCredential:
    role: str
    email: str
    password: str


REPLAY_CREDENTIALS: dict[str, ReplayCredential] = {
    "user": ReplayCredential(
        role="user",
        email="jina@travel.com",
        password="12341234a",
    ),
    "admin": ReplayCredential(
        role="admin",
        email="admin@travel.com",
        password="12341234a",
    ),
    "seller": ReplayCredential(
        role="seller",
        email="airluna@travel.com",
        password="12341234a",
    ),
}


def credential_for_role(role: str | None) -> ReplayCredential:
    """Return a role credential, defaulting to the normal user account."""
    normalized = str(role or "user").strip().lower()
    return REPLAY_CREDENTIALS.get(normalized, REPLAY_CREDENTIALS["user"])


def credential_for_url(url: str) -> ReplayCredential:
    """Choose the temporary account from the replay target URL."""
    normalized = str(url or "").lower()
    if ":8081" in normalized or "/admin/" in normalized:
        return REPLAY_CREDENTIALS["admin"]
    if "/seller/" in normalized or "/airline/" in normalized:
        return REPLAY_CREDENTIALS["seller"]
    return REPLAY_CREDENTIALS["user"]
