"""Classify missing/weak security response headers and cookies (7-4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from diagnosis.cookie_flags import parse_cookie_flags, scan_cookie_attributes


@dataclass
class ScanRules:
    strict: bool = True
    check_cookies: bool = True


@dataclass
class SecurityIssue:
    check_type: str
    reason: str
    severity: str
    header: str | None = None
    header_value: str | None = None
    cookie_name: str | None = None
    cookie_flags: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type,
            "reason": self.reason,
            "severity": self.severity,
            "header": self.header,
            "header_value": self.header_value,
            "cookie_name": self.cookie_name,
            "cookie_flags": self.cookie_flags,
        }


def _header_map(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).lower().strip(): str(v).strip() for k, v in headers.items()}


def _severity(rules: ScanRules, *, strict_sev: str, relaxed_sev: str) -> str:
    return strict_sev if rules.strict else relaxed_sev


def _parse_cookie_flags(cookie_line: str) -> dict[str, bool | str]:
    return parse_cookie_flags(cookie_line)


def _collect_set_cookies(headers: dict[str, str]) -> list[str]:
    cookies: list[str] = []
    for name, value in headers.items():
        if name.lower() == "set-cookie":
            cookies.append(value)
    return cookies


def scan_cookies(
    cookie_lines: list[str],
    *,
    is_https: bool,
    rules: ScanRules,
) -> list[SecurityIssue]:
    if not rules.check_cookies:
        return []
    flag_issues = scan_cookie_attributes(
        cookie_lines,
        is_https=is_https,
        strict=rules.strict,
    )
    return [
        SecurityIssue(
            check_type=issue.check_type,
            reason=issue.reason,
            severity=issue.severity,
            header="set-cookie",
            cookie_name=issue.cookie_name,
            cookie_flags=issue.cookie_flags,
        )
        for issue in flag_issues
    ]


def scan_response_security(
    url: str,
    headers: dict[str, str],
    *,
    rules: ScanRules | None = None,
    set_cookie_lines: list[str] | None = None,
) -> list[SecurityIssue]:
    """Return issues when security headers/cookies are missing or weak."""
    rules = rules or ScanRules()
    h = _header_map(headers)
    parsed = urlparse(url)
    is_https = (parsed.scheme or "").lower() == "https"
    issues: list[SecurityIssue] = []

    if is_https and not h.get("strict-transport-security"):
        issues.append(
            SecurityIssue(
                check_type="missing_hsts",
                reason="Strict-Transport-Security not set on HTTPS response",
                severity=_severity(rules, strict_sev="medium", relaxed_sev="low"),
                header="strict-transport-security",
            )
        )

    if not h.get("content-security-policy"):
        issues.append(
            SecurityIssue(
                check_type="missing_csp",
                reason="Content-Security-Policy not set",
                severity=_severity(rules, strict_sev="medium", relaxed_sev="low"),
                header="content-security-policy",
            )
        )

    xfo = h.get("x-frame-options", "")
    if not xfo:
        issues.append(
            SecurityIssue(
                check_type="missing_x_frame_options",
                reason="X-Frame-Options not set (clickjacking risk)",
                severity=_severity(rules, strict_sev="medium", relaxed_sev="low"),
                header="x-frame-options",
            )
        )
    elif xfo.upper() == "ALLOWALL":
        issues.append(
            SecurityIssue(
                check_type="weak_x_frame_options",
                reason="X-Frame-Options ALLOWALL is ineffective",
                severity="medium",
                header="x-frame-options",
                header_value=xfo,
            )
        )

    xcto = h.get("x-content-type-options", "")
    if not xcto or "nosniff" not in xcto.lower():
        issues.append(
            SecurityIssue(
                check_type="missing_nosniff",
                reason="X-Content-Type-Options nosniff not set",
                severity=_severity(rules, strict_sev="medium", relaxed_sev="low"),
                header="x-content-type-options",
                header_value=xcto or None,
            )
        )

    if rules.strict and not h.get("referrer-policy"):
        issues.append(
            SecurityIssue(
                check_type="missing_referrer_policy",
                reason="Referrer-Policy not set",
                severity="low",
                header="referrer-policy",
            )
        )

    if rules.strict and not h.get("permissions-policy") and not h.get("feature-policy"):
        issues.append(
            SecurityIssue(
                check_type="missing_permissions_policy",
                reason="Permissions-Policy not set",
                severity="low",
                header="permissions-policy",
            )
        )

    issues.extend(
        scan_cookies(
            set_cookie_lines if set_cookie_lines is not None else _collect_set_cookies(headers),
            is_https=is_https,
            rules=rules,
        )
    )
    return issues


def scan_rules_from_config(raw: dict[str, Any]) -> ScanRules:
    cfg = raw.get("diagnosis_7_4") or raw.get("scan_7_4") or {}
    return ScanRules(
        strict=bool(cfg.get("strict", True)),
        check_cookies=bool(cfg.get("check_cookies", True)),
    )
