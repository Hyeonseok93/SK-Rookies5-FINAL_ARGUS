"""Shared httpx context and login for 2-1 upload probes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.services.auth_probe_service import configured_login_entries, login_account_at
from app.services.zap_util import probe_url
from inventory.auth_util import auth_headers


@dataclass
class UploadProbeContext:
    client: httpx.Client
    base_url: str
    headers: dict[str, str]
    seller_id: int
    account_label: str


def resolve_target_base(raw: dict[str, Any]) -> str:
    targets = raw.get("targets") or []
    for entry in targets:
        if str(entry.get("name") or "") == "user-api":
            return probe_url(str(entry.get("base_url") or "http://localhost:8080").rstrip("/"))
    if targets:
        return probe_url(str(targets[0].get("base_url") or "http://localhost:8080").rstrip("/"))
    return probe_url("http://localhost:8080")


def _pick_login_url(raw: dict[str, Any]) -> str:
    auth_cfg = raw.get("auth") or {}
    entries = configured_login_entries(auth_cfg)
    for entry in entries:
        url = str(entry.get("url") or entry.get("login_url") or "")
        if url and "/admin/" not in url:
            return url
    if entries:
        first = entries[0]
        return str(first.get("url") or first.get("login_url") or "")
    base = resolve_target_base(raw)
    return f"{base}/api/v1/auth/login"


def login_for_upload(
    raw: dict[str, Any],
    *,
    email: str,
    password: str,
    timeout: float,
) -> dict[str, Any]:
    auth_cfg = raw.get("auth") or {}
    login_url = _pick_login_url(raw)
    return login_account_at(
        auth_cfg,
        {"email": email, "password": password},
        probe_url(login_url),
        timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)),
    )


def build_probe_context(
    raw: dict[str, Any],
    *,
    email: str,
    password: str,
    seller_id: int,
    timeout: float,
    label: str,
) -> UploadProbeContext:
    session = login_for_upload(raw, email=email, password=password, timeout=timeout)
    base = resolve_target_base(raw)
    client = httpx.Client(timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)))
    return UploadProbeContext(
        client=client,
        base_url=base,
        headers=auth_headers(session),
        seller_id=seller_id,
        account_label=label,
    )
