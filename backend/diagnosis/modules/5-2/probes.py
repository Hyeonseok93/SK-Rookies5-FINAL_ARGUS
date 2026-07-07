"""Execute baseline API probes and scan request/response for unmasked PII."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from diagnosis.probe_transport import HttpxTransport, ProbeTransport
from diagnosis.result import DiagnosisFinding
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint
from pii_rules import (
    analyze_http_plain,
    analyze_text,
    analyze_url_params,
    audit_sensitive_values,
    remediation_hint,
)
from targets import probe_base_url


def _body_bytes(body: str | bytes | None) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body or None
    return body.encode("utf-8") if body else None


def _finding_from_hit(
    *,
    hit,
    ep: Endpoint,
    auth_mode: str,
    direction: str,
    url: str,
    status_code: int,
) -> DiagnosisFinding:
    ev: dict[str, Any] = {
        "rule_id": hit.rule_id,
        "category": hit.category,
        "marker": hit.marker,
        "hint": hit.hint,
        "endpoint_id": ep.endpoint_id,
        "method": ep.method.upper(),
        "url": url,
        "direction": direction,
        "field_path": hit.field_path,
        "sample": hit.sample,
        "status_code": status_code,
        "auth_mode": auth_mode,
        "engine": "httpx",
        "source": "httpx",
        "remediation": remediation_hint(hit.rule_id),
    }
    msg = (
        f"[5-2][httpx][{auth_mode}][{direction}] {hit.hint} "
        f"on {ep.method.upper()} {ep.path} ({hit.rule_id})"
    )
    if hit.field_path:
        msg += f" @ {hit.field_path}"
    return DiagnosisFinding(severity=hit.severity, message=msg, evidence=ev)


def _empty_coverage() -> dict[str, int]:
    return {
        "requests": 0,
        "responses_with_body": 0,
        "response_bytes": 0,
        "status_2xx": 0,
        "status_401": 0,
        "status_403": 0,
        "status_other": 0,
        "connection_errors": 0,
        "json_bodies": 0,
        "sensitive_fields": 0,
        "emails_seen": 0,
        "phones_seen": 0,
        "masked_values": 0,
        "unmasked_values": 0,
    }


def _merge_coverage(total: dict[str, int], part: dict[str, int]) -> None:
    for key, value in part.items():
        total[key] = total.get(key, 0) + int(value)


def _record_response_coverage(
    coverage: dict[str, int],
    *,
    status_code: int,
    body: bytes,
    error: str | None = None,
) -> None:
    coverage["requests"] += 1
    if error or status_code <= 0:
        coverage["connection_errors"] = coverage.get("connection_errors", 0) + 1
        return
    if not body:
        return
    coverage["responses_with_body"] += 1
    coverage["response_bytes"] += len(body)
    if 200 <= status_code < 300:
        coverage["status_2xx"] += 1
    elif status_code == 401:
        coverage["status_401"] += 1
    elif status_code == 403:
        coverage["status_403"] += 1
    else:
        coverage["status_other"] += 1
    text = body.decode("utf-8", errors="replace").strip()
    if text.startswith("{") or text.startswith("["):
        coverage["json_bodies"] += 1
        _merge_coverage(coverage, audit_sensitive_values(body))


def probe_endpoint(
    ep: Endpoint,
    *,
    transport: ProbeTransport,
    timeout: float,
    interval_sec: float,
    auth_mode: str,
    auth_headers: dict[str, str],
    account_auth: dict[str, Any] | None = None,
    check_request_url: bool,
    check_request_body: bool,
    check_response_body: bool,
    check_http_plain: bool,
) -> tuple[list[DiagnosisFinding], bool, dict[str, int]]:
    probe = build_probe_request(ep, probe_base_fn=probe_base_url, account_auth=account_auth)
    method = str(probe["method"]).upper()
    url = str(probe["url"])
    headers = dict(probe.get("headers") or {})
    headers.update(auth_headers)
    body = probe.get("body") or ""
    body_b = _body_bytes(body)

    follow = method in ("GET", "HEAD", "OPTIONS")

    resp = transport.request(
        method,
        url,
        headers=headers,
        body=body_b,
        follow_redirects=follow,
        timeout=timeout,
    )
    if interval_sec > 0:
        time.sleep(interval_sec)

    findings: list[DiagnosisFinding] = []
    pii_hits = 0
    coverage = _empty_coverage()

    status_code = resp.status or 0
    _record_response_coverage(
        coverage,
        status_code=status_code,
        body=resp.body or b"",
        error=resp.error,
    )

    if check_request_url:
        for hit in analyze_url_params(url):
            pii_hits += 1
            findings.append(
                _finding_from_hit(
                    hit=hit,
                    ep=ep,
                    auth_mode=auth_mode,
                    direction="request_url",
                    url=url,
                    status_code=status_code,
                )
            )

    if check_request_body and body:
        for hit in analyze_text(body, field_path="request_body"):
            pii_hits += 1
            findings.append(
                _finding_from_hit(
                    hit=hit,
                    ep=ep,
                    auth_mode=auth_mode,
                    direction="request_body",
                    url=url,
                    status_code=status_code,
                )
            )

    if check_response_body and resp.body:
        for hit in analyze_text(resp.body, field_path="response_body"):
            pii_hits += 1
            findings.append(
                _finding_from_hit(
                    hit=hit,
                    ep=ep,
                    auth_mode=auth_mode,
                    direction="response_body",
                    url=url,
                    status_code=status_code,
                )
            )

    if check_http_plain:
        plain = analyze_http_plain(url, has_sensitive=pii_hits > 0)
        if plain:
            findings.append(
                _finding_from_hit(
                    hit=plain,
                    ep=ep,
                    auth_mode=auth_mode,
                    direction="transport",
                    url=url,
                    status_code=status_code,
                )
            )

    return findings, resp.status is None, coverage


def run_endpoints(
    endpoints: list[Endpoint],
    *,
    transport: ProbeTransport,
    timeout: float,
    interval_sec: float,
    passes: list[tuple[str, dict[str, str], dict[str, Any] | None]],
    check_request_url: bool,
    check_request_body: bool,
    check_response_body: bool,
    check_http_plain: bool,
    on_progress: Callable[..., None] | None = None,
    auth_pool: Any | None = None,
    build_passes: Callable[[Endpoint, list[dict[str, Any]]], list[tuple[str, dict[str, str], dict[str, Any] | None]]]
    | None = None,
) -> tuple[list[DiagnosisFinding], int, int, dict[str, int]]:
    findings: list[DiagnosisFinding] = []
    errors = 0
    done = 0
    total = len(endpoints)
    coverage = _empty_coverage()

    for ep in endpoints:
        current_passes = passes
        if auth_pool is not None and build_passes is not None:
            auth_pool.ensure_valid()
            current_passes = build_passes(ep, auth_pool.sessions())
        for auth_mode, auth_headers, account_auth in current_passes:
            batch, failed, cov = probe_endpoint(
                ep,
                transport=transport,
                timeout=timeout,
                interval_sec=interval_sec,
                auth_mode=auth_mode,
                auth_headers=auth_headers,
                account_auth=account_auth,
                check_request_url=check_request_url,
                check_request_body=check_request_body,
                check_response_body=check_response_body,
                check_http_plain=check_http_plain,
            )
            findings.extend(batch)
            _merge_coverage(coverage, cov)
            if failed:
                errors += 1
        done += 1
        if on_progress:
            on_progress(
                endpoints_done=done,
                endpoints_total=total,
                endpoint_id=ep.endpoint_id,
            )
    return findings, errors, done, coverage


_RAW_FINDING_KEYS = (
    "rule_id",
    "category",
    "method",
    "url",
    "direction",
    "field_path",
    "sample",
    "marker",
    "auth_mode",
    "status_code",
    "hint",
    "endpoint_id",
)


import re


def normalize_field_path_for_merge(field_path: str | None) -> str:
    if not field_path:
        return ""
    return re.sub(r"\[\d+\]", "[*]", field_path)


def serialize_raw_findings(items: list[DiagnosisFinding]) -> list[dict[str, Any]]:
    """Compact pre-collapse hits for audit UI (account × sample breakdown)."""
    rows: list[dict[str, Any]] = []
    for f in items:
        ev = f.evidence or {}
        if not ev.get("rule_id"):
            continue
        rows.append(
            {
                "severity": f.severity,
                "evidence": {key: ev[key] for key in _RAW_FINDING_KEYS if key in ev},
            }
        )
    return rows


def collapse_findings(
    items: list[DiagnosisFinding],
) -> tuple[list[DiagnosisFinding], dict[str, int]]:
    """Merge identical PII hits across auth sessions."""
    groups: dict[str, DiagnosisFinding] = {}
    auth_sets: dict[str, set[str]] = {}
    others: list[DiagnosisFinding] = []

    for f in items:
        ev = f.evidence or {}
        if not ev.get("rule_id"):
            others.append(f)
            continue
        key = "|".join(
            [
                str(ev.get("rule_id")),
                str(ev.get("endpoint_id")),
                str(ev.get("direction")),
                normalize_field_path_for_merge(str(ev.get("field_path") or "")),
                str(ev.get("marker") or ""),
            ]
        )
        auth = str(ev.get("auth_mode") or "anonymous")
        if key not in groups:
            groups[key] = f
            auth_sets[key] = {auth}
            continue
        auth_sets[key].add(auth)

    collapsed: list[DiagnosisFinding] = []
    for key, f in groups.items():
        modes = sorted(auth_sets[key])
        ev = dict(f.evidence or {})
        ev["auth_modes"] = modes
        ev["auth_mode"] = modes[0] if len(modes) == 1 else "multiple"
        msg = f.message
        if len(modes) > 1:
            msg = msg.replace(f"[{modes[0]}]", f"[{', '.join(modes)}]", 1)
        collapsed.append(DiagnosisFinding(severity=f.severity, message=msg, evidence=ev))

    return others + collapsed, {
        "raw_issues": len(items),
        "collapsed_issues": len(collapsed),
    }
