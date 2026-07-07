"""Software version disclosure + known end-of-life / vulnerable version detection (7-4).

CVE 항목의 현실적 구현. 외부 CVE DB 연동 없이(컨테이너 네트워크·오탐 리스크 회피)
두 단계로 점검한다. 대상 불문(도메인 하드코딩 없음).

  1. 버전 노출         → version_disclosure (medium)
     Server / X-Powered-By 등 응답 헤더로 SW·버전이 드러나면 지적.
     (수동 보고서의 "server_tokens off" 권고와 동일 취지)
  2. 알려진 EOL/취약 버전 → outdated_software (high)
     노출된 버전 문자열이 명백한 EOL/취약 버전 패턴과 일치하면 지적.
     오탐 방지를 위해 '확실히 지원종료된' 보수적 목록만 사용.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from diagnosis.result import DiagnosisFinding

# 버전을 흘리는 대표 헤더들
DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
)

# 명백히 EOL(지원종료)/취약으로 알려진 버전 패턴 — 보수적으로만.
# (major.minor 단위. 확실한 것만 넣어 오탐 최소화.)
KNOWN_EOL_PATTERNS: list[tuple[str, str]] = [
    (r"Apache/2\.0\.", "Apache httpd 2.0 (EOL)"),
    (r"Apache/2\.2\.", "Apache httpd 2.2 (EOL 2017)"),
    (r"nginx/0\.", "nginx 0.x (EOL)"),
    (r"nginx/1\.([0-9]|1[0-3])\.", "nginx < 1.14 (EOL)"),
    (r"PHP/5\.", "PHP 5.x (EOL)"),
    (r"PHP/7\.[0-3]\.", "PHP 7.0-7.3 (EOL)"),
    (r"OpenSSL/0\.", "OpenSSL 0.x (EOL/critical CVEs)"),
    (r"OpenSSL/1\.0\.", "OpenSSL 1.0.x (EOL)"),
    (r"Tomcat/[5-7]\.", "Apache Tomcat 5-7 (EOL)"),
    (r"IIS/[567]\.", "Microsoft IIS 5-7 (EOL)"),
    (r"jetty/[0-8]\.", "Jetty <= 8 (EOL)"),
]


def _remediation(check_type: str) -> str:
    hints = {
        "version_disclosure": (
            "Suppress version banners (e.g. nginx server_tokens off, "
            "remove X-Powered-By) to reduce fingerprinting"
        ),
        "outdated_software": (
            "Upgrade to a supported version and apply security patches; "
            "review CVEs for the disclosed component"
        ),
    }
    return hints.get(check_type, "Keep software up to date and hide version banners")


def _finding(severity: str, check_type: str, reason: str, base_url: str, header: str,
             header_value: str, **extra: Any) -> DiagnosisFinding:
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-4] {reason} on {base_url}",
        evidence={
            "rule_id": "7-4-weak-security",
            "source": "version",
            "engine": "httpx",
            "check_type": check_type,
            "reason": reason,
            "base_url": base_url,
            "url": base_url,
            "label": base_url,
            "header": header,
            "header_value": header_value,
            "remediation": _remediation(check_type),
            **extra,
        },
    )


def _scan_headers(base_url: str, headers: dict[str, str], findings: list[DiagnosisFinding]) -> None:
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    for name in DISCLOSURE_HEADERS:
        value = h.get(name)
        if not value:
            continue
        # 1) 알려진 EOL/취약 버전인지 먼저 확인 (high)
        matched_eol = None
        for pattern, label in KNOWN_EOL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                matched_eol = label
                break
        if matched_eol:
            findings.append(
                _finding("high", "outdated_software",
                         f"Outdated/EOL software disclosed: {matched_eol}",
                         base_url, name, value, matched=matched_eol)
            )
        # 2) 버전 숫자가 노출됐는지 (medium) — EOL 여부와 별개로 노출 자체가 지적 대상
        if re.search(r"\d+\.\d+", value):
            findings.append(
                _finding("medium", "version_disclosure",
                         f"Software version disclosed via `{name}` header",
                         base_url, name, value)
            )


def check_versions_for_base_urls(
    base_urls: list[str],
    *,
    timeout: float = 8.0,
    on_progress: Any | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "targets": 0,
        "checked": 0,
        "unreachable": 0,
        "issues": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
    }
    seen: set[str] = set()

    with httpx.Client() as client:
        for base in base_urls:
            base = (base or "").strip().rstrip("/")
            if not base:
                continue
            parsed = urlparse(base)
            key = f"{parsed.scheme}://{parsed.netloc}"
            if key in seen:
                continue
            seen.add(key)
            stats["targets"] += 1
            before = len(findings)
            try:
                resp = client.get(
                    base, timeout=timeout, follow_redirects=True,
                    headers={"User-Agent": "ARGUS-7-4/1.0", "Accept": "*/*"},
                )
                stats["checked"] += 1
                _scan_headers(base, dict(resp.headers), findings)
            except httpx.HTTPError:
                stats["unreachable"] += 1

            for f in findings[before:]:
                sev = f.severity
                if sev in stats["by_severity"]:
                    stats["by_severity"][sev] += 1
                if sev != "info":
                    stats["issues"] += 1
            if on_progress:
                on_progress(endpoint_id=base)

    return findings, stats
