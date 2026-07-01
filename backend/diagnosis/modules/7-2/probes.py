"""HTTP probes for directory listing (7-2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch_get(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
) -> tuple[int | None, str, str, str | None]:
    try:
        resp = client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "ARGUS-7-2/1.0", "Accept": "text/html,*/*"},
        )
        body = resp.text[:120_000]
        return resp.status_code, body, resp.headers.get("content-type", ""), None
    except httpx.HTTPError as exc:
        return None, "", "", str(exc)[:200]


def run_listing_probes(
    probe_targets: list[dict[str, str]],
    *,
    classify_fn: Any,
    remediation_fn: Callable[[str], str],
    fingerprint_fn: Callable[[str], str],
    timeout: float = 8.0,
    probe_base_fn: Callable[[str], str] | None = None,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "targets": len(probe_targets),
        "probed": 0,
        "unreachable": 0,
        "issues": 0,
        "by_severity": {"medium": 0, "low": 0, "info": 0},
    }

    baseline_bodies: dict[str, tuple[str, str]] = {}
    bases_seen: set[str] = set()

    with httpx.Client() as client:
        for target in probe_targets:
            base_url = target.get("base_url") or target["probe_url"]
            if base_url in bases_seen:
                continue
            bases_seen.add(base_url)
            mapped = probe_base_fn(base_url) if probe_base_fn else base_url.rstrip("/")
            status, body, _ct, _err = _fetch_get(client, f"{mapped}/", timeout=timeout)
            fp = fingerprint_fn(body) if status == 200 and body else ""
            baseline_bodies[mapped] = (body, fp)

        for target in probe_targets:
            url = target["probe_url"]
            label = target.get("label") or url
            base_url = target.get("base_url") or url
            source = target.get("source") or "wordlist"
            variant = target.get("variant") or "trailing_slash"

            stats["probed"] += 1
            status, body, content_type, err = _fetch_get(client, url, timeout=timeout)

            if err:
                stats["unreachable"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"[7-2] Unreachable probe target: {label}",
                        evidence={
                            "rule_id": "7-2-directory-listing",
                            "url": url,
                            "base_url": base_url,
                            "error": err,
                        },
                    )
                )
                continue

            mapped_base = probe_base_fn(base_url) if probe_base_fn else base_url.rstrip("/")
            baseline_body, baseline_fp = baseline_bodies.get(mapped_base, ("", ""))

            issue = classify_fn(
                body,
                content_type=content_type,
                baseline_body=baseline_body,
                baseline_fp=baseline_fp,
                http_status=status,
            )
            if issue is None:
                continue

            stats["issues"] += 1
            sev = issue.severity
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1

            findings.append(
                DiagnosisFinding(
                    severity=sev,
                    message=(
                        f"[7-2] Directory listing ({issue.listing_type}): "
                        f"`{label}` — {issue.reason}"
                    ),
                    evidence={
                        "rule_id": "7-2-directory-listing",
                        "source": "httpx",
                        "engine": "httpx",
                        "base_url": base_url,
                        "url": url,
                        "label": label,
                        "probe_source": source,
                        "url_variant": variant,
                        "http_status": status,
                        "content_type": content_type,
                        "reason": issue.reason,
                        "listing_type": issue.listing_type,
                        "matched_patterns": issue.matched_patterns,
                        "file_link_count": issue.link_count,
                        "remediation": remediation_fn(issue.listing_type),
                        "body_preview": body[:500].replace("\n", " ").strip(),
                    },
                )
            )

            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(probe_targets),
                    endpoint_id=label,
                )

    return findings, stats
