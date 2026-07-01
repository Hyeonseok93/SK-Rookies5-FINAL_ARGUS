"""Execute 6-1 probes and collect findings."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from diagnosis.probe_transport import HttpxTransport, ProbeTransport
from diagnosis.result import DiagnosisFinding
from error_rules import analyze_error_response, remediation_hint
from inventory.schema import Endpoint
from payloads import PayloadSpec, build_payload_suite
from triggers import ProbeJob, iter_body_jobs, iter_header_jobs, iter_method_jobs, iter_param_jobs, iter_path_jobs


@dataclass
class RequestBudget:
    """max_requests <= 0 means no request cap (run all planned probes)."""

    max_requests: int
    sent: int = 0
    by_family: dict[str, int] = field(default_factory=dict)

    @property
    def unlimited(self) -> bool:
        return self.max_requests <= 0

    def exhausted(self) -> bool:
        return not self.unlimited and self.sent >= self.max_requests

    def consume(self, family: str) -> bool:
        if self.exhausted():
            return False
        self.sent += 1
        self.by_family[family] = self.by_family.get(family, 0) + 1
        return True


def _body_bytes(job: ProbeJob) -> bytes | None:
    if not job.body:
        return None
    if isinstance(job.body, bytes):
        return job.body
    return job.body.encode("utf-8")


def _execute_job(
    transport: ProbeTransport,
    job: ProbeJob,
    *,
    timeout: float,
    auth_headers: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    headers = dict(job.headers)
    headers.update(auth_headers)
    resp = transport.request(
        job.method,
        job.url,
        headers=headers,
        body=_body_bytes(job),
        follow_redirects=False,
        timeout=timeout,
    )
    if resp.status is None:
        return 0, {}, b""
    return resp.status, resp.headers, resp.body


def _finding_from_hit(
    *,
    hit,
    ep: Endpoint,
    job: ProbeJob,
    auth_mode: str,
    status_code: int,
    snippet: str,
    engine: str,
) -> DiagnosisFinding:
    ev: dict[str, Any] = {
        "rule_id": hit.rule_id,
        "category": hit.category,
        "marker": hit.marker,
        "hint": hit.hint,
        "endpoint_id": ep.endpoint_id,
        "method": job.method,
        "url": job.url,
        "trigger_family": job.family,
        "trigger_id": job.trigger_id,
        "status_code": status_code,
        "auth_mode": auth_mode,
        "param_name": job.param_name,
        "payload_id": job.payload_id,
        "body_snippet": snippet[:500],
        "remediation": remediation_hint(hit.rule_id),
        "engine": engine,
        "source": engine,
    }
    if job.extra:
        ev.update(job.extra)
    msg = (
        f"[6-1][{engine}][{auth_mode}][{job.family}] {hit.hint} on "
        f"{ep.method.upper()} {ep.path} ({hit.rule_id})"
    )
    return DiagnosisFinding(severity=hit.severity, message=msg, evidence=ev)


def _snippet(body: bytes) -> str:
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = repr(body[:500])
    return text[:800]


def run_endpoint_probes(
    ep: Endpoint,
    *,
    transport: ProbeTransport,
    engine: str,
    payloads: list[PayloadSpec],
    timeout: float,
    interval_sec: float,
    budget: RequestBudget,
    auth_mode: str,
    auth_headers: dict[str, str],
    enable: dict[str, bool],
) -> tuple[list[DiagnosisFinding], int]:
    findings: list[DiagnosisFinding] = []
    errors = 0

    iterators: list[tuple[str, Any]] = []
    if enable.get("param", True):
        iterators.append(("param", iter_param_jobs(ep, payloads)))
    if enable.get("body", True):
        iterators.append(("body", iter_body_jobs(ep)))
    if enable.get("path", True):
        iterators.append(("path", iter_path_jobs(ep, payloads)))
    if enable.get("method", True):
        iterators.append(("method", iter_method_jobs(ep)))
    if enable.get("header", True):
        iterators.append(("header", iter_header_jobs(ep)))

    for _family, iterator in iterators:
        for job in iterator:
            if not budget.consume(job.family):
                return findings, errors
            status, hdrs, body = _execute_job(
                transport, job, timeout=timeout, auth_headers=auth_headers
            )
            if status == 0:
                errors += 1
            else:
                hits = analyze_error_response(
                    status_code=status,
                    headers={k: str(v) for k, v in hdrs.items()},
                    body=body,
                )
                snip = _snippet(body)
                for hit in hits:
                    findings.append(
                        _finding_from_hit(
                            hit=hit,
                            ep=ep,
                            job=job,
                            auth_mode=auth_mode,
                            status_code=status,
                            snippet=snip,
                            engine=engine,
                        )
                    )
            if interval_sec > 0:
                time.sleep(interval_sec)
    return findings, errors


def run_endpoints_probes(
    endpoints: list[Endpoint],
    *,
    transport: ProbeTransport,
    engine: str,
    payloads: list[PayloadSpec],
    timeout: float,
    interval_sec: float,
    budget: RequestBudget,
    passes: list[tuple[str, dict[str, str]]],
    enable: dict[str, bool],
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], int, int]:
    """Run all endpoints × auth passes until request budget is exhausted."""
    findings: list[DiagnosisFinding] = []
    errors = 0
    endpoints_done = 0
    total = len(endpoints)

    for ep in endpoints:
        if budget.exhausted():
            break
        for auth_mode, auth_headers in passes:
            if budget.exhausted():
                break
            batch, batch_errors = run_endpoint_probes(
                ep,
                transport=transport,
                engine=engine,
                payloads=payloads,
                timeout=timeout,
                interval_sec=interval_sec,
                budget=budget,
                auth_mode=auth_mode,
                auth_headers=auth_headers,
                enable=enable,
            )
            findings.extend(batch)
            errors += batch_errors
        endpoints_done += 1
        if on_progress:
            on_progress(
                endpoints_done=endpoints_done,
                endpoints_total=total,
                requests_sent=budget.sent,
                requests_cap=budget.max_requests if budget.max_requests > 0 else None,
                endpoint_id=ep.endpoint_id,
                engine=engine,
            )
    return findings, errors, endpoints_done


def collapse_auth_findings(
    items: list[DiagnosisFinding],
) -> tuple[list[DiagnosisFinding], dict[str, int]]:
    """Merge identical leaks across anonymous / account sessions (per engine)."""
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
                str(ev.get("engine") or "httpx"),
                str(ev.get("rule_id")),
                str(ev.get("endpoint_id")),
                str(ev.get("trigger_family")),
                str(ev.get("trigger_id")),
                str(ev.get("param_name") or ""),
                str(ev.get("payload_id") or ""),
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
        if len(modes) > 1:
            msg = f.message.replace(f"[{modes[0]}]", f"[{', '.join(modes)}]", 1)
        else:
            msg = f.message
        collapsed.append(DiagnosisFinding(severity=f.severity, message=msg, evidence=ev))

    return others + collapsed, {
        "raw_leaks": len(items),
        "collapsed_leaks": len(collapsed),
    }


def build_payloads_from_config(cfg: dict[str, Any]) -> list[PayloadSpec]:
    lengths = cfg.get("long_lengths") or [256, 1000, 5000]
    try:
        lengths = [int(x) for x in lengths]
    except (TypeError, ValueError):
        lengths = [256, 1000, 5000]
    return build_payload_suite(lengths, include_long=bool(cfg.get("include_long", True)))
