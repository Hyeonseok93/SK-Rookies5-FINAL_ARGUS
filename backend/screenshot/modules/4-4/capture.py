"""4-4 후보를 익명 및 인증 상태로 다시 전송해 실제 요청/응답 증거를 캡처 — screenshot/modules/5-2/capture.py를 미러링"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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


def reprobe(
    endpoint: Endpoint,
    *,
    account_auth: dict[str, Any] | None,
    transport: HttpxTransport,
    timeout: float,
) -> ReprobeResult:
    """후보를 다시 전송
      `account_auth=None` → 익명(Authorization/Cookie 없음)"""
    probe = build_probe_request(endpoint, probe_base_fn=probe_base_url, account_auth=account_auth)
    body = str(probe.get("body") or "")
    body_bytes = body.encode("utf-8") if body else None

    resp = transport.request(
        str(probe["method"]),
        str(probe["url"]),
        dict(probe.get("headers") or {}),
        body_bytes,
        follow_redirects=False,
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
