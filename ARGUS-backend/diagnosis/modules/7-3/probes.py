"""HTTP probes for response header disclosure (7-3)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch_headers(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
) -> tuple[int | None, dict[str, str], str | None]:
    """Try HEAD, then GET; return status, headers, error."""
    last_err: str | None = None
    for method in ("HEAD", "GET"):
        try:
            resp = client.request(
                method,
                url,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "ARGUS-7-3/1.0", "Accept": "*/*"},
            )
            return resp.status_code, dict(resp.headers), None
        except httpx.HTTPError as exc:
            last_err = str(exc)[:200]
    return None, {}, last_err


def run_header_probes(
    probe_targets: list[dict[str, str]],
    *,
    scan_headers_fn: Any,
    classify_fn: Any,
    timeout: float = 8.0,
    scan_rules: Any = None,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    Probe each URL and emit findings for disclosed headers.

    scan_headers_fn / classify_fn injected to avoid importlib circular loads in scanner.
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "targets": len(probe_targets),
        "probed": 0,
        "unreachable": 0,
        "issues": 0,
        "strict": bool(getattr(scan_rules, "strict", True)),
        "by_severity": {"medium": 0, "low": 0, "info": 0},
    }

    with httpx.Client() as client:
        for target in probe_targets:
            url = target["probe_url"]
            label = target.get("label") or url
            base_url = target.get("base_url") or url
            source = target.get("source") or "base"

            status, headers, err = _fetch_headers(client, url, timeout=timeout)
            stats["probed"] += 1

            if err:
                stats["unreachable"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"[7-3] Unreachable probe target: {label}",
                        evidence={
                            "rule_id": "7-3-header-disclosure",
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

            issues = scan_headers_fn(headers)
            if not issues:
                continue

            for issue in issues:
                stats["issues"] += 1
                sev = issue.severity
                if sev in stats["by_severity"]:
                    stats["by_severity"][sev] += 1

                findings.append(
                    DiagnosisFinding(
                        severity=sev,
                        message=(
                            f"[7-3] Response header `{issue.header}` exposes stack info "
                            f"({issue.reason}): `{issue.value}` on {label}"
                        ),
                        evidence={
                            "rule_id": "7-3-header-disclosure",
                            "source": "httpx",
                            "engine": "httpx",
                            "base_url": base_url,
                            "url": url,
                            "label": label,
                            "probe_source": source,
                            "http_status": status,
                            "header": issue.header,
                            "header_value": issue.value,
                            "reason": issue.reason,
                            "remediation": _remediation_hint(issue.header),
                            "all_response_headers": _safe_header_snapshot(headers),
                        },
                    )
                )

    return findings, stats


def _remediation_hint(header: str) -> str:
    hints = {
        "server": "Apache ServerToken Prod / nginx server_tokens off / Tomcat server attribute",
        "x-powered-by": "Remove X-Powered-By (IIS URL Rewrite outbound rule, framework config)",
        "x-aspnet-version": "Remove X-AspNet-Version in Web.config outboundRules",
        "x-aspnetmvc-version": "Remove X-AspNetMvc-Version in Web.config outboundRules",
    }
    return hints.get(header, "Remove or genericize response header per KISA 7-3")


def _safe_header_snapshot(headers: dict[str, str]) -> dict[str, str]:
    """Keep disclosure-relevant headers only (avoid huge Set-Cookie)."""
    hints = (
        "server",
        "powered",
        "aspnet",
        "generator",
        "runtime",
        "version",
        "backend",
        "environment",
        "drupal",
        "jenkins",
        "technology",
        "framework",
        "via",
        "cache",
    )
    out: dict[str, str] = {}
    for name, val in headers.items():
        key = name.lower()
        if key == "server" or key.startswith("x-") and any(h in key for h in hints):
            out[name] = val
    return out
