"""httpx probes for guideline 1-5 (redirect, CORS, crossdomain)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# pyrefly: ignore [missing-import]
import httpx

from diagnosis.exceptions import DiagnosisCancelled
from diagnosis.result import DiagnosisFinding

_MAX_WORKERS = 8

# job마다 새 httpx.Client()를 만들면 매 요청 새 TCP/TLS 커넥션을 맺는다 — 스레드별로
# 하나씩 재사용해 커넥션 풀링 이득을 본다 (reflected_detector.py의 _session()과 동일 패턴).
_thread_local = threading.local()


def _raise_if_cancelled() -> None:
    from app.services import diagnosis_progress as dp
    from diagnosis.exceptions import DiagnosisCancelled

    if dp.is_cancel_requested():
        raise DiagnosisCancelled("User cancelled diagnosis")


def _client() -> httpx.Client:
    client = getattr(_thread_local, "client", None)
    if client is None:
        client = httpx.Client()
        _thread_local.client = client
    return client


def _request(
    client: httpx.Client,
    job: dict[str, Any],
    *,
    timeout: float,
) -> tuple[int | None, dict[str, str], str | None]:
    method = str(job.get("method") or "GET").upper()
    url = str(job["url"])
    # job["headers"]는 원본 baseline 요청 시점에 캡처된 헤더라 Content-Length가 그 body 기준으로
    # 박혀 있다. 여기서 body를 페이로드로 교체하면 길이가 달라져 h11이
    # "Too much data for declared Content-Length"로 요청 자체를 거부한다 — httpx가 content=로
    # 실제 길이를 다시 계산하도록 stale Content-Length/Transfer-Encoding은 제거한다.
    headers = {
        k: v
        for k, v in (job.get("headers") or {}).items()
        if k.lower() not in ("content-length", "transfer-encoding")
    }
    body = job.get("body") or ""
    try:
        resp = client.request(
            method,
            url,
            headers=headers,
            content=body if body else None,
            timeout=timeout,
            follow_redirects=False,
        )
        return resp.status_code, dict(resp.headers), None
    except httpx.HTTPError as exc:
        return None, {}, str(exc)[:200]


def _location(headers: dict[str, str]) -> str | None:
    for key, val in headers.items():
        if key.lower() == "location":
            return val
    return None


def _redirect_job_finding(
    job: dict[str, Any],
    *,
    sink_base: str,
    is_open_redirect_fn: Any,
    timeout: float,
) -> tuple[DiagnosisFinding | None, bool]:
    """단일 job의 baseline/test 요청을 보내고 open redirect 여부를 판별한다.

    Returns:
        (finding 또는 None, errored) — errored=True면 baseline/test 요청이 둘 다 실패.
    """
    client = _client()
    phase = job.get("phase") or "?"

    base_status, base_headers, base_err = _request(
        client,
        {
            "method": job["method"],
            "url": job["baseline_url"],
            "headers": job.get("headers"),
            "body": job.get("baseline_body", job.get("body")),
        },
        timeout=timeout,
    )
    test_status, test_headers, test_err = _request(
        client,
        {"method": job["method"], "url": job["test_url"], "headers": job.get("headers"), "body": job.get("body")},
        timeout=timeout,
    )
    if base_err and test_err:
        return None, True

    baseline_loc = _location(base_headers)
    test_loc = _location(test_headers)
    if not is_open_redirect_fn(
        test_status,
        test_loc,
        sink_base=sink_base,
        baseline_location=baseline_loc,
    ):
        return None, False

    phase_label = "param fuzz" if phase == "A" else "path sweep"
    finding = DiagnosisFinding(
        severity="high",
        message=(
            f"Open redirect ({phase_label}): {job.get('param_name')} → "
            f"Location {test_loc}"
        ),
        evidence={
            "rule_id": "1-5-open-redirect",
            "trigger": f"open_redirect_phase_{phase.lower()}",
            "engine": "httpx",
            "phase": phase,
            "endpoint_id": job.get("endpoint_id"),
            "base_url": job.get("base_url"),
            "path": job.get("path"),
            "param_name": job.get("param_name"),
            "param_in": job.get("param_in"),
            "baseline_url": job.get("baseline_url"),
            "test_url": job.get("test_url"),
            "baseline_status": base_status,
            "test_status": test_status,
            "baseline_location": baseline_loc,
            "location": test_loc,
            "sink_token": job.get("sink_token"),
            "related_sections": ["1-5"],
        },
    )
    return finding, False


def run_redirect_jobs(
    jobs: list[dict[str, Any]],
    *,
    sink_base: str,
    is_open_redirect_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """job마다 baseline+test 2회 요청 — job이 최대 수천 개까지 생길 수 있어(targets.py의
    max_phase_a_jobs/max_phase_b_jobs) 순차 실행하면 블로킹 요청이 누적돼 매우 느려진다.
    job끼리 완전히 독립적인 요청이므로 reflected_bridge.py와 동일하게 스레드풀로
    병렬화한다 (스레드별 httpx.Client 재사용으로 커넥션 풀링도 함께 적용).
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "redirect_jobs": len(jobs),
        "probed": 0,
        "errors": 0,
        "open_redirects": 0,
        "phase_a": 0,
        "phase_b": 0,
    }
    seen: set[str] = set()
    lock = threading.Lock()

    def _run_one(job: dict[str, Any]) -> tuple[dict[str, Any], DiagnosisFinding | None, bool]:
        # 이미 스레드풀 큐에 들어간 뒤 아직 시작되지 않은 job은 여기서 바로 빠진다 —
        # 실행 중인 요청 자체를 강제 중단할 수는 없지만(최대 timeout초 뒤 자연 종료),
        # 아직 안 쏜 요청까지 굳이 다 쏘지는 않게 막는다.
        _raise_if_cancelled()
        finding, errored = _redirect_job_finding(
            job, sink_base=sink_base, is_open_redirect_fn=is_open_redirect_fn, timeout=timeout,
        )
        return job, finding, errored

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_run_one, job) for job in jobs]
        cancelled = False
        for future in as_completed(futures):
            try:
                job, finding, errored = future.result()
            except DiagnosisCancelled:
                # 아직 시작 안 된 나머지 future는 취소하고, 이미 실행 중인 것들만
                # 자연 종료를 기다린 뒤(위 with 블록 종료 시) 취소로 마무리한다.
                cancelled = True
                for f in futures:
                    f.cancel()
                break
            phase = job.get("phase") or "?"

            with lock:
                stats["probed"] += 1
                if phase == "A":
                    stats["phase_a"] += 1
                elif phase == "B":
                    stats["phase_b"] += 1
                if errored:
                    stats["errors"] += 1
                probed_done = stats["probed"]

            if on_progress:
                on_progress(
                    endpoints_done=probed_done,
                    endpoints_total=len(jobs),
                    endpoint_id=str(job.get("test_url") or "")[:80],
                )

            if finding is None:
                continue

            ev = finding.evidence or {}
            dedupe = f"{ev.get('test_url')}|{ev.get('param_name')}|{ev.get('location')}"
            with lock:
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                stats["open_redirects"] += 1
            findings.append(finding)

    if cancelled:
        raise DiagnosisCancelled("User cancelled diagnosis")
    return findings, stats


def run_cors_probes(
    targets: list[dict[str, str]],
    *,
    probe_origin: str,
    analyze_cors_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"cors_targets": len(targets), "probed": 0, "issues": 0}

    headers = {
        "Origin": probe_origin,
        "Access-Control-Request-Method": "GET",
        "User-Agent": "ARGUS-1-5/1.0",
    }

    with httpx.Client() as client:
        for target in targets:
            _raise_if_cancelled()
            url = target["probe_url"]
            stats["probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(targets),
                    endpoint_id=url[:80],
                )
            try:
                resp = client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
            except httpx.HTTPError:
                continue
            for issue in analyze_cors_fn(dict(resp.headers), probe_origin=probe_origin):
                stats["issues"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity=str(issue.get("severity") or "medium"),
                        message=f"CORS misconfiguration ({issue.get('reason')}): {url}",
                        evidence={
                            "rule_id": "1-5-cors-misconfig",
                            "trigger": str(issue.get("reason")),
                            "engine": "httpx",
                            "url": url,
                            "base_url": target.get("base_url"),
                            "probe_origin": probe_origin,
                            "http_status": resp.status_code,
                            **issue,
                            "related_sections": ["1-5", "7-4"],
                        },
                    )
                )
    return findings, stats


def run_crossdomain_probes(
    targets: list[dict[str, str]],
    *,
    analyze_crossdomain_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {"crossdomain_targets": len(targets), "probed": 0, "issues": 0}

    with httpx.Client() as client:
        for target in targets:
            _raise_if_cancelled()
            url = target["probe_url"]
            stats["probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["probed"],
                    endpoints_total=len(targets),
                    endpoint_id=url[:80],
                )
            try:
                resp = client.get(
                    url,
                    timeout=timeout,
                    follow_redirects=True,
                    headers={"User-Agent": "ARGUS-1-5/1.0", "Accept": "application/xml,text/xml,*/*"},
                )
            except httpx.HTTPError:
                continue
            if resp.status_code >= 400:
                continue
            body = resp.text or ""
            if "cross-domain-policy" not in body.lower() and "<allow-access-from" not in body.lower():
                continue
            for issue in analyze_crossdomain_fn(body):
                stats["issues"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity=str(issue.get("severity") or "info"),
                        message=f"Permissive crossdomain.xml ({issue.get('domain')}): {url}",
                        evidence={
                            "rule_id": "1-5-crossdomain-permissive",
                            "trigger": str(issue.get("reason")),
                            "engine": "httpx",
                            "url": url,
                            "base_url": target.get("base_url"),
                            "http_status": resp.status_code,
                            **issue,
                            "related_sections": ["1-5"],
                        },
                    )
                )
    return findings, stats
