"""HTTP probes for backup / test file exposure (3-6)."""

from __future__ import annotations

from typing import Any, Callable

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch_get(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int | None, str, str, str | None]:
    headers = {"User-Agent": "ARGUS-3-6/1.0", "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        )
        body = resp.text[:120_000]
        return resp.status_code, body, resp.headers.get("content-type", ""), None
    except httpx.HTTPError as exc:
        return None, "", "", str(exc)[:200]


def run_file_probes(
    probe_targets: list[dict[str, str]],
    *,
    classify_fn: Any,
    remediation_fn: Callable[[str], str],
    fingerprint_fn: Callable[[str], str],
    timeout: float = 8.0,
    probe_base_fn: Callable[[str], str] | None = None,
    auth_mode: str = "anonymous",
    request_headers: dict[str, str] | None = None,
    account_email: str | None = None,
    login_label: str | None = None,
    login_url: str | None = None,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "auth_mode": auth_mode,
        "targets": len(probe_targets),
        "probed": 0,
        "unreachable": 0,
        "issues": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
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
            status, body, _ct, _err = _fetch_get(
                client, f"{mapped}/", timeout=timeout, extra_headers=request_headers
            )
            fp = fingerprint_fn(body) if status == 200 and body else ""
            baseline_bodies[mapped] = (body, fp)

        prefix = f"[3-6][{auth_mode}]"
        for target in probe_targets:
            url = target["probe_url"]
            label = target.get("label") or url
            path = target.get("path") or urlparse_path(url)
            base_url = target.get("base_url") or url
            source = target.get("source") or "wordlist"

            stats["probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(probe_targets),
                    endpoint_id=label[:80],
                )
            status, body, content_type, err = _fetch_get(
                client, url, timeout=timeout, extra_headers=request_headers
            )

            if err:
                stats["unreachable"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"{prefix} Unreachable probe target: {label}",
                        evidence={
                            "rule_id": "3-6-backup-test-file",
                            "engine": "httpx",
                            "auth_mode": auth_mode,
                            "url": url,
                            "base_url": base_url,
                            "path": path,
                            "error": err,
                        },
                    )
                )
                continue

            mapped_base = probe_base_fn(base_url) if probe_base_fn else base_url.rstrip("/")
            baseline_body, baseline_fp = baseline_bodies.get(mapped_base, ("", ""))

            issue = classify_fn(
                path,
                http_status=status,
                body=body,
                content_type=content_type,
                baseline_body=baseline_body,
                baseline_fp=baseline_fp,
            )
            if issue is None:
                continue

            stats["issues"] += 1
            sev = issue.severity
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1

            ev: dict[str, Any] = {
                "rule_id": "3-6-backup-test-file",
                "source": "httpx",
                "engine": "httpx",
                "auth_mode": auth_mode,
                "account_email": account_email,
                "related_sections": ["2-2", "3-6"],
                "base_url": base_url,
                "url": url,
                "path": path,
                "label": label,
                "probe_source": source,
                "http_status": status,
                "content_type": content_type,
                "file_type": issue.file_type,
                "reason": issue.reason,
                "trigger": issue.trigger,
                "remediation": remediation_fn(issue.file_type),
                "body_preview": body[:500].replace("\n", " ").strip(),
            }
            if login_label:
                ev["login_label"] = login_label
            if login_url:
                ev["login_url"] = login_url
            findings.append(
                DiagnosisFinding(
                    severity=sev,
                    message=(
                        f"{prefix} Backup/test file ({issue.file_type}): "
                        f"`{path}` — {issue.reason}"
                    ),
                    evidence=ev,
                )
            )

    return findings, stats


def urlparse_path(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path or "/"
