"""Re-issue the original 5-2 probe for a finding to capture real request/response evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diagnosis.probe_auth import session_auth_mode
from diagnosis.probe_transport import HttpxTransport
from inventory.net import probe_base_url
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint


@dataclass
class ReprobeResult:
    ok: bool
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status_code: int | None
    response_headers: dict[str, str]
    response_body: bytes
    error: str | None = None


def find_endpoint(endpoints: list[Endpoint], endpoint_id: str) -> Endpoint | None:
    for ep in endpoints:
        if ep.endpoint_id == endpoint_id:
            return ep
    return None


def resolve_session_for_auth_mode(
    auth_mode: str,
    evidence: dict[str, Any],
    sessions: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, bool]:
    """Match a finding's recorded auth_mode string back to a live session.

    Returns (session_or_none, matched) — matched is False when the finding was
    authenticated but no live session for that account exists any more (e.g. the
    scan ran under a rotated test account); the caller falls back to anonymous.
    """
    target = auth_mode
    if target == "multiple":
        modes = evidence.get("auth_modes") or []
        target = str(modes[0]) if modes else "anonymous"
    if target in ("", "anonymous"):
        return None, True
    for session in sessions:
        if session_auth_mode(session) == target:
            return session, True
    return None, False


def reprobe(
    endpoint: Endpoint,
    *,
    account_auth: dict[str, Any] | None,
    transport: HttpxTransport,
    timeout: float,
) -> ReprobeResult:
    probe = build_probe_request(endpoint, probe_base_fn=probe_base_url, account_auth=account_auth)
    body = str(probe.get("body") or "")
    body_bytes = body.encode("utf-8") if body else None

    resp = transport.request(
        str(probe["method"]),
        str(probe["url"]),
        headers=dict(probe.get("headers") or {}),
        body=body_bytes,
        timeout=timeout,
    )
    return ReprobeResult(
        ok=resp.error is None,
        method=str(probe["method"]),
        url=str(probe["url"]),
        request_headers=dict(probe.get("headers") or {}),
        request_body=body,
        status_code=resp.status,
        response_headers=dict(resp.headers or {}),
        response_body=resp.body or b"",
        error=resp.error,
    )
