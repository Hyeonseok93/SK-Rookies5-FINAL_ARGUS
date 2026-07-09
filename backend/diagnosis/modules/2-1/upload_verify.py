"""
2-1 업로드 검증 엔진 — 정탐/오탐 판별.

업로드 성공(200/201) 후 저장된 URL에 follow-up GET을 보내
실제로 파일이 실행·접근 가능한지 검증합니다.

판별 기준:
  정탐  (TRUE_POSITIVE)  : 파일 내용이 실행되거나 그대로 서빙됨
  오탐  (FALSE_POSITIVE) : 저장됐지만 접근 불가 or 안전하게 다운로드만 허용
  수동검토 (REVIEW)      : 검증 URL 없음 / 외부 CDN / 네트워크 오류
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


# ── 페이로드 마커 ─────────────────────────────────────────────────────────────
# security_rules.py 페이로드 파일의 content에 삽입된 탐지 문자열
PAYLOAD_MARKERS: list[str] = [
    "UPLOAD_TEST",
    "UPLOAD_TEST_PHP",
    "UPLOAD_TEST_JSPX",
    "VULN_TEST_UPLOAD",
    "UPLOAD_TEST_JSPX",
    "<?php",
    "<%@",
    "<jsp:",
    "<jspx:",
    "document.location",   # HTML XSS payload
    "SVG XSS",
    "attacker.com",
]

# ── Content-Type 분류 ─────────────────────────────────────────────────────────
# 브라우저에서 실행·렌더링될 수 있는 타입 → 정탐 가능성
EXECUTABLE_CONTENT_TYPES: frozenset[str] = frozenset({
    "text/html",
    "text/plain",
    "text/xml",
    "application/x-php",
    "application/x-httpd-php",
    "application/javascript",
    "text/javascript",
    "image/svg+xml",
    "application/xhtml+xml",
})

# 서버가 안전하게 처리한 것으로 볼 수 있는 타입
SAFE_CONTENT_TYPES: frozenset[str] = frozenset({
    "application/octet-stream",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
})

# CDN 도메인 패턴 (검증 불가 케이스)
CDN_PATTERNS: list[str] = [
    "s3.amazonaws.com",
    "s3-",
    "cloudfront.net",
    "akamaized.net",
    "cdn.",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "r2.cloudflarestorage.com",
]


@dataclass
class VerifyResult:
    """follow-up GET 검증 결과."""

    verdict: str                      # "정탐" | "오탐" | "수동검토"
    reason: str                       # 판별 근거 (한국어 설명)
    verify_url: str                   # 검증한 URL
    verify_status: int = 0            # follow-up GET 상태코드 (0 = 요청 안 됨)
    content_type: str = ""            # 응답 Content-Type
    body_snippet: str = ""            # 응답 body 앞 300자
    is_forced_download: bool = False  # Content-Disposition: attachment 여부
    marker_found: str | None = None   # 발견된 페이로드 마커
    filename_changed: bool = False    # 서버가 파일명/확장자를 변경했는지
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "verify_url": self.verify_url,
            "verify_status": self.verify_status,
            "content_type": self.content_type,
            "body_snippet": self.body_snippet,
            "is_forced_download": self.is_forced_download,
            "marker_found": self.marker_found,
            "filename_changed": self.filename_changed,
            **self.extra,
        }


def _is_cdn_url(url: str) -> bool:
    """외부 CDN URL인지 판별."""
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return False
    return any(pat in hostname for pat in CDN_PATTERNS)


def _find_marker(body: str) -> str | None:
    """응답 body에서 페이로드 마커를 탐색."""
    body_lower = body.lower()
    for marker in PAYLOAD_MARKERS:
        if marker.lower() in body_lower:
            return marker
    return None


def _normalize_content_type(raw: str) -> str:
    """Content-Type에서 파라미터(charset 등) 제거 후 소문자 반환."""
    return raw.split(";")[0].strip().lower()


def _is_forced_download(headers: dict[str, str]) -> bool:
    """Content-Disposition: attachment 여부 확인."""
    disp = headers.get("content-disposition") or headers.get("Content-Disposition") or ""
    return "attachment" in disp.lower()


def _check_filename_changed(stored_url: str, original_filename: str) -> bool:
    """저장 URL의 파일명이 원본과 다른지 확인 (확장자 변환 탐지)."""
    try:
        url_path = urlparse(stored_url).path
        url_filename = url_path.split("/")[-1].lower()
        orig_ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""
        url_ext = url_filename.rsplit(".", 1)[-1].lower() if "." in url_filename else ""
        return orig_ext != url_ext and url_ext != ""
    except Exception:
        return False


def verify_stored_file(
    stored_url: str,
    filename: str,
    original_content: bytes,
    *,
    timeout: float = 8.0,
    extra_headers: dict[str, str] | None = None,
) -> VerifyResult:
    """
    저장된 파일 URL에 GET 요청을 보내 정탐/오탐을 판별합니다.

    Args:
        stored_url: 업로드 응답에서 추출한 파일 URL
        filename: 업로드 시 사용한 파일명
        original_content: 업로드한 파일 내용 (마커 포함 여부 확인용)
        timeout: GET 요청 타임아웃(초)
        extra_headers: 추가 요청 헤더 (인증 등 불필요 — 보통 public URL)
    """
    import httpx

    # ── CDN URL → 자동 수동검토 ────────────────────────────────────────────
    if _is_cdn_url(stored_url):
        return VerifyResult(
            verdict="수동검토",
            reason=f"외부 CDN URL — 실제 접근 가능 여부는 CDN 정책에 따라 다름: {stored_url}",
            verify_url=stored_url,
        )

    # ── follow-up GET ──────────────────────────────────────────────────────
    # Docker 환경에서 테스트 중인 경우 서버가 반환한 localhost를 host.docker.internal로 치환
    if "localhost" in stored_url:
        stored_url = stored_url.replace("localhost", "host.docker.internal")

    try:
        # 인증 헤더 없이 anonymous GET (저장 파일은 보통 public URL)
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers=extra_headers or {},
        ) as client:
            resp = client.get(stored_url)
    except httpx.TimeoutException:
        return VerifyResult(
            verdict="수동검토",
            reason="follow-up GET 타임아웃 — 수동으로 URL 접근 확인 필요",
            verify_url=stored_url,
        )
    except Exception as exc:
        return VerifyResult(
            verdict="수동검토",
            reason=f"follow-up GET 오류: {exc}",
            verify_url=stored_url,
        )

    status = resp.status_code
    raw_ct = resp.headers.get("content-type") or resp.headers.get("Content-Type") or ""
    ct = _normalize_content_type(raw_ct)

    try:
        body_text = resp.content[:2000].decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    body_snippet = body_text[:300]
    forced_dl = _is_forced_download(dict(resp.headers))
    fname_changed = _check_filename_changed(stored_url, filename)

    # ── 접근 차단 ──────────────────────────────────────────────────────────
    if status in (403, 401):
        return VerifyResult(
            verdict="오탐",
            reason=f"저장됐지만 {status}로 접근 차단 — 서버 사이드 접근제어 작동 중",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
        )

    if status == 404:
        return VerifyResult(
            verdict="오탐",
            reason="저장됐지만 404 — 파일이 웹에 노출되지 않음 (격리 저장소 가능성)",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
        )

    # ── 비정상 응답 ────────────────────────────────────────────────────────
    if status not in (200, 206):
        return VerifyResult(
            verdict="수동검토",
            reason=f"비정상 응답 코드 {status} — 수동 확인 필요",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
            body_snippet=body_snippet,
        )

    # ── 이하 status == 200 ────────────────────────────────────────────────

    # 강제 다운로드 (Content-Disposition: attachment)
    if forced_dl:
        return VerifyResult(
            verdict="오탐",
            reason="파일이 attachment로 다운로드 강제 — 브라우저 실행 불가",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
            body_snippet=body_snippet,
            is_forced_download=True,
        )

    # 안전한 Content-Type으로 변환됨
    if ct in SAFE_CONTENT_TYPES:
        # 이미지로 저장됐지만 내용 확인
        marker = _find_marker(body_text)
        if marker:
            return VerifyResult(
                verdict="정탐",
                reason=f"이미지 Content-Type이지만 body에 페이로드 마커 발견: '{marker}'",
                verify_url=stored_url,
                verify_status=status,
                content_type=ct,
                body_snippet=body_snippet,
                marker_found=marker,
            )
        return VerifyResult(
            verdict="오탐",
            reason=f"Content-Type이 '{ct}'로 변환됨 — 서버가 안전하게 처리",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
            body_snippet=body_snippet,
            filename_changed=fname_changed,
        )

    # 파일명/확장자가 변경됨 → 서버가 변환
    if fname_changed:
        marker = _find_marker(body_text)
        if not marker:
            return VerifyResult(
                verdict="오탐",
                reason="서버가 파일명/확장자를 변경함 — sanitize 처리됨",
                verify_url=stored_url,
                verify_status=status,
                content_type=ct,
                body_snippet=body_snippet,
                filename_changed=True,
            )

    # 페이로드 마커 탐색 (핵심 판별)
    marker = _find_marker(body_text)
    if marker:
        return VerifyResult(
            verdict="정탐",
            reason=f"응답 body에 페이로드 마커 '{marker}' 발견 — 파일 내용이 그대로 서빙/실행됨",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
            body_snippet=body_snippet,
            marker_found=marker,
        )

    # 실행 가능한 Content-Type으로 서빙 중
    if ct in EXECUTABLE_CONTENT_TYPES:
        # SVG에 <script> 포함 여부 추가 확인
        if ct == "image/svg+xml" and "<script" in body_text.lower():
            return VerifyResult(
                verdict="정탐",
                reason="SVG가 실행 가능한 타입으로 서빙 + <script> 태그 포함 — XSS 가능",
                verify_url=stored_url,
                verify_status=status,
                content_type=ct,
                body_snippet=body_snippet,
                marker_found="<script>",
            )
        return VerifyResult(
            verdict="정탐",
            reason=f"실행 가능한 Content-Type '{ct}'으로 파일 서빙 — 마커는 없지만 위험",
            verify_url=stored_url,
            verify_status=status,
            content_type=ct,
            body_snippet=body_snippet,
        )

    # 판별 불가
    return VerifyResult(
        verdict="수동검토",
        reason=f"Content-Type '{ct}', 마커 없음 — 직접 URL 접근하여 확인 필요",
        verify_url=stored_url,
        verify_status=status,
        content_type=ct,
        body_snippet=body_snippet,
    )


def verify_or_skip(
    stored_url: str | None,
    filename: str,
    original_content: bytes,
    *,
    timeout: float = 8.0,
) -> VerifyResult | None:
    """
    stored_url이 없으면 None 반환 (검증 스킵).
    있으면 verify_stored_file() 실행.
    """
    if not stored_url:
        return None
    return verify_stored_file(
        stored_url,
        filename,
        original_content,
        timeout=timeout,
    )
