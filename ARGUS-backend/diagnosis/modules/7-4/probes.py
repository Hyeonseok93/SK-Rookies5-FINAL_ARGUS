"""HTTP probes for weak security configuration (7-4)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch_response(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
) -> tuple[int | None, dict[str, str], list[str], str | None]:
    """GET response; return status, headers, set-cookie lines, error."""
    try:
        resp = client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "ARGUS-7-4/1.0", "Accept": "*/*"},
        )
        cookies = resp.headers.get_list("set-cookie")
        return resp.status_code, dict(resp.headers), cookies, None
    except httpx.HTTPError as exc:
        return None, {}, [], str(exc)[:200]


def run_security_probes(
    probe_targets: list[dict[str, str]],
    *,
    scan_response_fn: Any,
    timeout: float = 8.0,
    scan_rules: Any = None,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "targets": len(probe_targets),
        "probed": 0,
        "unreachable": 0,
        "issues": 0,
        "strict": bool(getattr(scan_rules, "strict", True)),
        "check_cookies": bool(getattr(scan_rules, "check_cookies", True)),
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
    }

    with httpx.Client() as client:
        for target in probe_targets:
            url = target["probe_url"]
            label = target.get("label") or url
            base_url = target.get("base_url") or url
            source = target.get("source") or "base"

            status, headers, cookie_lines, err = _fetch_response(client, url, timeout=timeout)
            stats["probed"] += 1

            if err:
                stats["unreachable"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"[7-4] Unreachable probe target: {label}",
                        evidence={
                            "rule_id": "7-4-weak-security",
                            "url": url,
                            "base_url": base_url,
                            "error": err,
                        },
                    )
                )
                continue

            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(probe_targets),
                    endpoint_id=label,
                )

            issues = scan_response_fn(url, headers, set_cookie_lines=cookie_lines)
            if not issues:
                continue

            for issue in issues:
                stats["issues"] += 1
                sev = issue.severity
                if sev in stats["by_severity"]:
                    stats["by_severity"][sev] += 1

                subject = issue.header or "set-cookie"
                if issue.cookie_name:
                    subject = f"cookie `{issue.cookie_name}`"

                findings.append(
                    DiagnosisFinding(
                        severity=sev,
                        message=(
                            f"[7-4] Weak security config ({issue.reason}): "
                            f"{subject} on {label}"
                        ),
                        evidence={
                            "rule_id": "7-4-weak-security",
                            "source": "httpx",
                            "engine": "httpx",
                            "base_url": base_url,
                            "url": url,
                            "label": label,
                            "probe_source": source,
                            "http_status": status,
                            "check_type": issue.check_type,
                            "header": issue.header,
                            "header_value": issue.header_value,
                            "cookie_name": issue.cookie_name,
                            "cookie_flags": issue.cookie_flags,
                            "reason": issue.reason,
                            "remediation": _remediation_hint(issue.check_type),
                            "security_headers": _safe_header_snapshot(headers),
                        },
                    )
                )

    return findings, stats


def _remediation_hint(check_type: str) -> str:
    hints = {
        "missing_hsts": "Add Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains)",
        "no_transport_encryption": "Serve the application over HTTPS/TLS, then add Strict-Transport-Security (max-age=31536000; includeSubDomains)",
        "missing_csp": "Define Content-Security-Policy appropriate for the application",
        "missing_x_frame_options": "Set X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors)",
        "weak_x_frame_options": "Replace ALLOWALL with DENY or SAMEORIGIN",
        "missing_nosniff": "Set X-Content-Type-Options: nosniff",
        "missing_referrer_policy": "Set Referrer-Policy (e.g. strict-origin-when-cross-origin)",
        "xxss_protection_disabled": "Set X-XSS-Protection: 1; mode=block, or remove it and rely on Content-Security-Policy",
        "missing_xxss_protection": "Add X-XSS-Protection: 1; mode=block (legacy) or enforce via Content-Security-Policy",
        "missing_permissions_policy": "Set Permissions-Policy to restrict browser features",
        "cookie_missing_secure": "Add Secure flag to Set-Cookie on HTTPS",
        "cookie_missing_httponly": "Add HttpOnly to session cookies",
        "cookie_missing_samesite": "Set SameSite=Lax or Strict on cookies",
        "cookie_samesite_none_insecure": "SameSite=None requires Secure flag",
    }
    return hints.get(check_type, "Harden HTTP security headers per KISA 7-4")


def _safe_header_snapshot(headers: dict[str, str]) -> dict[str, str]:
    keys = (
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "feature-policy",
        "set-cookie",
    )
    out: dict[str, str] = {}
    for name, val in headers.items():
        if name.lower() in keys:
            if name.lower() == "set-cookie":
                out[name] = val[:120] + ("…" if len(val) > 120 else "")
            else:
                out[name] = val
    return out