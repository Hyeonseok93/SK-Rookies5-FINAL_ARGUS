"""Collect probe jobs for guideline 1-5."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse

from inventory.auth_util import auth_headers
from inventory.load import load_api_tree
from inventory.net import probe_base_url, probe_url
from diagnosis.replay.normalize import collect_probe_base_urls as collect_base_urls, filter_endpoints_by_probe_bases
from inventory.probe_build import build_probe_request
from inventory.schema import ApiTree, Endpoint, build_full_url, split_path_query
from parsers.parse_endpoints import materialize_path_params

ProbeMode = Literal["base_only", "sample", "full"]

REDIRECT_PARAM_NAMES: tuple[str, ...] = (
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirectUrl",
    "return",
    "returnUrl",
    "return_url",
    "returl",
    "retUrl",
    "next",
    "continue",
    "url",
    "target",
    "dest",
    "destination",
    "goto",
    "go",
    "forward",
    "fwd",
    "to",
    "out",
    "redir",
    "link",
    "callback",
    "continueTo",
)

SKIP_FUZZ_PARAM_NAMES = frozenset(
    {
        "page",
        "size",
        "limit",
        "offset",
        "sort",
        "order",
        "direction",
        "q",
        "keyword",
        "search",
        "id",
        "ids",
    }
)


def resolve_sink_base(raw_config: dict[str, Any] | None) -> str:
    cfg = (raw_config or {}).get("diagnosis_1_5") or {}
    env = os.environ.get("ARGUS_REDIRECT_SINK_BASE", "").strip()
    base = str(cfg.get("redirect_sink_base") or env or "").strip()
    if base:
        return base.rstrip("/")
    probe_host = os.environ.get("ARGUS_PROBE_HOST", "").strip()
    if probe_host:
        port = str(cfg.get("redirect_sink_port") or os.environ.get("ARGUS_REDIRECT_SINK_PORT") or "8001")
        return f"http://{probe_host}:{port}/argus-redirect-sink"
    return "http://127.0.0.1:8001/argus-redirect-sink"


def resolve_cors_probe_origin(raw_config: dict[str, Any] | None, sink_base: str) -> str:
    cfg = (raw_config or {}).get("diagnosis_1_5") or {}
    origin = str(cfg.get("cors_probe_origin") or "").strip()
    if origin:
        return origin
    host = urlparse(sink_base).hostname
    if host:
        return f"https://cors-probe.{host}"
    return "https://argus-cors-probe.invalid"


def _probe_base_fn(url: str) -> str:
    return probe_url(url.rstrip("/"))


def should_fuzz_param(name: str, *, param_in: str) -> bool:
    if param_in not in ("query", "body", "form"):
        return False
    if name.lower() in SKIP_FUZZ_PARAM_NAMES:
        return False
    return True


def sink_token_url(sink_base: str, run_id: str, probe_id: str) -> str:
    base = sink_base.rstrip("/")
    return f"{base}/r/{run_id}/{probe_id}"


def _sample_endpoints(endpoints: list[Endpoint], *, mode: ProbeMode, sample_size: int) -> list[Endpoint]:
    if mode == "full":
        return endpoints
    if mode == "base_only":
        return []
    if len(endpoints) <= sample_size:
        return endpoints
    step = max(1, len(endpoints) // sample_size)
    return [endpoints[i] for i in range(0, len(endpoints), step)][:sample_size]


def _path_key(ep: Endpoint) -> tuple[str, str]:
    clean, _ = split_path_query(ep.path)
    return ep.base_url.rstrip("/"), clean


def build_phase_a_jobs(
    tree: ApiTree | None,
    *,
    raw_config: dict[str, Any] | None = None,
    sink_base: str,
    run_id: str,
    probe_mode: ProbeMode,
    sample_size: int,
    max_params_per_endpoint: int,
    max_jobs: int,
    account_auth: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if tree is None:
        return []
    jobs: list[dict[str, Any]] = []
    endpoints = _sample_endpoints(
        filter_endpoints_by_probe_bases(list(tree.endpoints), raw_config),
        mode=probe_mode,
        sample_size=sample_size,
    )
    probe_counter = 0

    for ep in endpoints:
        if ep.method.upper() not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
            continue
        fuzz_params = [
            p
            for p in ep.request_params
            if should_fuzz_param(p.name, param_in=p.in_)
        ][:max_params_per_endpoint]
        if not fuzz_params:
            continue

        try:
            # account_auth 없이 보내면 인증이 필요한 엔드포인트는 컨트롤러 로직에
            # 도달하기도 전에 401로 막혀, 페이로드가 반사/리다이렉트될 여지 자체가
            # 없다 — 로그인된 세션으로 보내야 실제 취약점 여부를 판단할 수 있다.
            baseline_probe = build_probe_request(ep, probe_base_fn=_probe_base_fn, account_auth=account_auth)
        except Exception:
            continue

        for param in fuzz_params:
            if len(jobs) >= max_jobs:
                return jobs
            probe_id = f"a{probe_counter}"
            probe_counter += 1
            token = sink_token_url(sink_base, run_id, probe_id)
            test_probe = _probe_with_param_override(
                ep,
                baseline_probe,
                param_name=param.name,
                param_in=param.in_,
                value=token,
            )
            if test_probe is None:
                continue
            jobs.append(
                {
                    "phase": "A",
                    "probe_id": probe_id,
                    "endpoint_id": ep.endpoint_id,
                    "method": test_probe["method"],
                    "baseline_url": baseline_probe["url"],
                    "test_url": test_probe["url"],
                    "param_name": param.name,
                    "param_in": param.in_,
                    "headers": test_probe.get("headers") or baseline_probe.get("headers") or {},
                    "body": test_probe.get("body") or "",
                    "baseline_body": baseline_probe.get("body") or "",
                    "base_url": ep.base_url,
                    "path": ep.path,
                    "sink_token": token,
                }
            )
    return jobs


def _probe_with_param_override(
    ep: Endpoint,
    baseline: dict[str, Any],
    *,
    param_name: str,
    param_in: str,
    value: str,
) -> dict[str, Any] | None:
    method = baseline["method"]
    headers = dict(baseline.get("headers") or {})
    body = baseline.get("body") or ""

    if param_in == "query":
        parsed = urlparse(baseline["url"])
        q = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        q[param_name] = value
        path = parsed.path or "/"
        test_url = build_full_url(f"{parsed.scheme}://{parsed.netloc}", path, q)
        return {"method": method, "url": test_url, "headers": headers, "body": body}

    if param_in in ("body", "form") and method in ("POST", "PUT", "PATCH"):
        import json

        ctype = headers.get("Content-Type", headers.get("content-type", "")).lower()
        if "json" in ctype and body:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    obj = dict(obj)
                    obj[param_name] = value
                    return {
                        "method": method,
                        "url": baseline["url"],
                        "headers": headers,
                        "body": json.dumps(obj, ensure_ascii=False),
                    }
            except json.JSONDecodeError:
                return None
        if "form" in ctype or param_in == "form":
            q = parse_qs(body, keep_blank_values=True) if body else {}
            flat = {k: v[0] if v else "" for k, v in q.items()}
            flat[param_name] = value
            new_body = urlencode(flat)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers.pop("content-type", None)
            return {"method": method, "url": baseline["url"], "headers": headers, "body": new_body}
    return None


def build_phase_b_jobs(
    tree: ApiTree | None,
    *,
    raw_config: dict[str, Any] | None = None,
    sink_base: str,
    run_id: str,
    probe_mode: ProbeMode,
    sample_size: int,
    max_jobs: int,
    account_auth: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if tree is None or probe_mode == "base_only":
        return []
    seen_paths: set[tuple[str, str]] = set()
    jobs: list[dict[str, Any]] = []
    scoped = filter_endpoints_by_probe_bases(list(tree.endpoints), raw_config)
    endpoints = _sample_endpoints(
        [ep for ep in scoped if ep.method.upper() in ("GET", "HEAD")],
        mode=probe_mode,
        sample_size=max(sample_size * 3, sample_size),
    )

    # phase A(build_probe_request 경유)와 동일하게, 인증 없이 보내면 로그인이 필요한
    # 엔드포인트는 컨트롤러 로직에 도달하기 전에 401로 막혀 리다이렉트 여부를 판단할
    # 수 없다 — 여기는 build_probe_request를 거치지 않고 헤더를 직접 구성하므로
    # auth_headers()로 동일한 인증 헤더를 수동으로 얹어준다.
    base_headers = {"Accept": "*/*", "User-Agent": "ARGUS-1-5/1.0", **auth_headers(account_auth)}

    probe_counter = 0
    for ep in endpoints:
        key = _path_key(ep)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        clean_path, existing_q = split_path_query(ep.path)
        materialized = materialize_path_params(clean_path, None)
        base = _probe_base_fn(ep.base_url)

        for param_name in REDIRECT_PARAM_NAMES:
            if len(jobs) >= max_jobs:
                return jobs
            if param_name in existing_q:
                continue
            probe_id = f"b{probe_counter}"
            probe_counter += 1
            token = sink_token_url(sink_base, run_id, probe_id)
            query = dict(existing_q)
            query[param_name] = token
            test_url = build_full_url(base, materialized, query)
            baseline_url = build_full_url(base, materialized, existing_q or None)
            jobs.append(
                {
                    "phase": "B",
                    "probe_id": probe_id,
                    "endpoint_id": ep.endpoint_id,
                    "method": "GET",
                    "baseline_url": baseline_url,
                    "test_url": test_url,
                    "param_name": param_name,
                    "param_in": "query",
                    "headers": dict(base_headers),
                    "body": "",
                    "base_url": ep.base_url,
                    "path": clean_path,
                    "sink_token": token,
                }
            )
    return jobs


def build_cors_targets(bases: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for base in bases:
        probe = _probe_base_fn(base)
        if probe in seen:
            continue
        seen.add(probe)
        out.append({"base_url": base, "probe_url": probe, "label": probe})
    return out


def build_crossdomain_targets(bases: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for base in bases:
        probe = _probe_base_fn(base)
        url = f"{probe.rstrip('/')}/crossdomain.xml"
        if url in seen:
            continue
        seen.add(url)
        out.append({"base_url": base, "probe_url": url, "label": url})
    return out


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]
