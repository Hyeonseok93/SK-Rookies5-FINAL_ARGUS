"""익명 중요 페이지 응답 판정 오라클"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

LOGIN_LOCATION_RE = re.compile(r"(?i)/(login|signin|sign-in|auth|sso)(/|\?|$)")
LOGIN_BODY_RE = re.compile(rb"(?is)(type\s*=\s*['\"]password|\blog[ -]?in\b|\bsign[ -]?in\b|\xeb\xb9\x84\xeb\xb0\x80\xeb\xb2\x88\xed\x98\xb8|\xeb\xa1\x9c\xea\xb7\xb8\xec\x9d\xb8)")
PROTECTED_DATA_RE = re.compile(rb"(?is)(logout|sign[ -]?out|dashboard|admin|member|account|profile|order|payment|\xeb\xa1\x9c\xea\xb7\xb8\xec\x95\x84\xec\x9b\x83|\xeb\xa7\x88\xec\x9d\xb4\xed\x8e\x98\xec\x9d\xb4\xec\xa7\x80|\xea\xb4\x80\xeb\xa6\xac\xec\x9e\x90)")


def _success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def is_login_page(body: bytes) -> bool:
    return bool(LOGIN_BODY_RE.search(body[:500_000]))


def classify_unauth_page(
    *,
    path: str,
    kind: str,
    anonymous: Any,
    authenticated: Any | None,
    protected_signal: bool = False,
    origin_enforces_auth: bool = False,
    public_shell_sha256: str | None = None,
):
    location = anonymous.headers.get("location") or anonymous.headers.get("Location") or ""
    status = anonymous.http_status
    login_gate = status in (401, 403) or (
        status is not None and 300 <= status < 400 and bool(LOGIN_LOCATION_RE.search(urlparse(location).path or location))
    ) or is_login_page(anonymous.body)
    # 익명이 401/403/로그인 리다이렉트/로그인 페이지 → 정상 차단 → finding 없음
    if login_gate or status in (404, 405) or (status or 0) >= 500:
        return None
    if not _success(status):
        return None

    anon_fp = anonymous.fingerprint
    meta: dict[str, Any] = {
        "anonymous_http_status": status, "anonymous_sha256": anon_fp["sha256"],
        "anonymous_size": anon_fp["size"], "location": location, "login_gate": False,
        "protected_signal": bool(protected_signal),
        "origin_enforces_auth": bool(origin_enforces_auth),
    }
    protected_marker = bool(PROTECTED_DATA_RE.search(anonymous.body[:500_000]))

    # SPA 클라이언트측 가드: 공개 루트 셸과 동일 + 보호 데이터 마커 없음 → 서버 노출로 확정하지 않음
    if kind == "frontend" and public_shell_sha256 and anon_fp["sha256"] == public_shell_sha256 and not protected_marker:
        return "info", "client_side_guard_only", {**meta, "public_shell_identical": True}

    # 공개 엔드포인트(로그인이 필요해야 한다는 긍정적 근거 없음) → 4-4 취약으로 보지 않음
    # 익명==인증 동일 응답은 오히려 '개인화·보호되지 않는 공개 자원'의 정상 특징
    if not protected_signal:
        return None

    if authenticated is not None:
        auth_fp = authenticated.fingerprint
        meta.update({
            "authenticated_http_status": authenticated.http_status,
            "authenticated_sha256": auth_fp["sha256"], "authenticated_size": auth_fp["size"],
            "bodies_identical": anon_fp["sha256"] == auth_fp["sha256"],
        })
        # 유효 세션조차 거부되는 자원인데 익명은 접근됨 → 강한 이상 신호
        if authenticated.http_status in (401, 403):
            return "high", "anon_ok_auth_denied", meta

    # 로그인이 필요해야 할 페이지가 익명 2xx로 접근됨
    # 같은 출처가 다른 곳에서 인증을 강제(401/403 관측)한다면 실제 인증 누락일 확률이 높다 → high
    # 그렇지 않으면(전면 공개 API일 수 있음) 수동 확인 필요 → medium
    severity = "high" if origin_enforces_auth else "medium"
    if authenticated is None:
        return severity, "unauth_access_no_account", {**meta, "auth_comparison": "no_test_account"}
    if _success(authenticated.http_status):
        return severity, "unauth_access_confirmed", meta
    return None
