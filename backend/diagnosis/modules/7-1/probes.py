"""HTTP method probes for guideline 7-1 (TRACE + OPTIONS Allow)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    timeout: float,
) -> tuple[int | None, dict[str, str], bytes, str | None]:
    try:
        resp = client.request(
            method,
            url,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "ARGUS-7-1/1.0", "Accept": "*/*"},
        )
        body = resp.content or b""
        return resp.status_code, dict(resp.headers), body, None
    except httpx.HTTPError as exc:
        return None, {}, b"", str(exc)[:200]


def _issue_to_finding(
    issue: Any,
    *,
    url: str,
    label: str,
    base_url: str,
    source: str,
    http_method: str,
    status: int | None,
) -> DiagnosisFinding:
    methods = ", ".join(issue.matched_methods) if issue.matched_methods else (issue.method or "")
    if issue.issue_type == "trace_echo":
        message = f"[7-1] TRACE enabled (body echo): {label}"
    elif issue.issue_type == "allow_dangerous":
        message = f"[7-1] Allow header lists dangerous method(s) ({methods}): {label}"
    elif issue.issue_type == "allow_risky":
        message = f"[7-1] Allow header lists PUT/DELETE ({methods}): {label}"
    else:
        message = f"[7-1] Insecure HTTP method ({issue.reason}): {label}"

    return DiagnosisFinding(
        severity=issue.severity,
        message=message,
        evidence={
            "rule_id": "7-1-insecure-http-method",
            "source": source,
            "engine": "httpx",
            "issue_type": issue.issue_type,
            "reason": issue.reason,
            "http_method": http_method,
            "method": issue.method,
            "matched_methods": list(issue.matched_methods),
            "allow_header": issue.allow_header,
            "url": url,
            "label": label,
            "base_url": base_url,
            "status": status,
            "trigger": f"httpx_{issue.issue_type}",
        },
    )


def run_method_probes(
    probe_targets: list[dict[str, str]],
    *,
    classify_trace_fn: Any,
    classify_allow_fn: Any,
    strict_risky: bool,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "targets": len(probe_targets),
        "probed": 0,
        "unreachable": 0,
        "issues": 0,
        "strict_risky": strict_risky,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "trace_probes": 0,
        "options_probes": 0,
    }

    with httpx.Client() as client:
        for target in probe_targets:
            url = target["probe_url"]
            label = target.get("label") or url
            base_url = target.get("base_url") or url
            parsed = urlparse(url)
            request_path = parsed.path or "/"

            stats["probed"] += 1
            unreachable = True

            stats["trace_probes"] += 1
            trace_status, _trace_headers, trace_body, trace_err = _fetch(
                client, "TRACE", url, timeout=timeout
            )
            if trace_err:
                pass
            else:
                unreachable = False
                trace_issue = classify_trace_fn(
                    trace_status,
                    trace_body,
                    request_path=request_path,
                )
                if trace_issue:
                    findings.append(
                        _issue_to_finding(
                            trace_issue,
                            url=url,
                            label=label,
                            base_url=base_url,
                            source="httpx",
                            http_method="TRACE",
                            status=trace_status,
                        )
                    )
                    stats["issues"] += 1
                    stats["by_severity"][trace_issue.severity] = (
                        stats["by_severity"].get(trace_issue.severity, 0) + 1
                    )

            stats["options_probes"] += 1
            opt_status, opt_headers, _opt_body, opt_err = _fetch(
                client, "OPTIONS", url, timeout=timeout
            )
            if opt_err:
                if unreachable:
                    stats["unreachable"] += 1
                    findings.append(
                        DiagnosisFinding(
                            severity="info",
                            message=f"[7-1] Unreachable probe target: {label}",
                            evidence={
                                "rule_id": "7-1-insecure-http-method",
                                "url": url,
                                "base_url": base_url,
                                "error": opt_err,
                            },
                        )
                    )
                continue

            unreachable = False
            allow = opt_headers.get("Allow") or opt_headers.get("allow")
            for allow_issue in classify_allow_fn(allow, strict_risky=strict_risky):
                findings.append(
                    _issue_to_finding(
                        allow_issue,
                        url=url,
                        label=label,
                        base_url=base_url,
                        source="httpx",
                        http_method="OPTIONS",
                        status=opt_status,
                    )
                )
                stats["issues"] += 1
                stats["by_severity"][allow_issue.severity] = (
                    stats["by_severity"].get(allow_issue.severity, 0) + 1
                )

            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(probe_targets),
                    endpoint_id=label,
                )

    return findings, stats
