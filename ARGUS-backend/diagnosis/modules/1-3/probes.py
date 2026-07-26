"""Baseline + single-field mutation probes for guideline 1-3.

Ported from ARGUS_Backend/scanners/param_manipulation/manipulator.py, adapted to
build a full valid baseline body (via inventory.probe_build) and mutate one field
at a time — the original ARGUS_Backend code sent only {param: value} as the whole
body, dropping every other required field.
"""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.services.zap_util import probe_url
from diagnosis.probe_transport import HttpxTransport, ProbeResponse
from inventory.probe_build import build_body_object, build_probe_request
from inventory.schema import Endpoint

MAX_MUTATIONS_PER_PARAM = 5


def inject_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    flat = {k: v[0] if v else "" for k, v in qs.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


def inject_json_body(body: str, name: str, value: Any, *, baseline: dict[str, Any] | None = None) -> str:
    """Replace only `name`; keep every other baseline field unchanged."""
    if baseline is not None:
        data = dict(baseline)
    else:
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            return body
    data[name] = value
    return json.dumps(data, ensure_ascii=False)


def _original_query_value(url: str, name: str) -> str | None:
    qs = parse_qs(urlparse(url).query)
    values = qs.get(name)
    return values[0] if values else None


def run_param_probes(
    candidates: list[Endpoint],
    *,
    transport: HttpxTransport,
    auth: dict[str, Any] | None,
    sensitive_params_fn: Callable[[Endpoint], list[tuple[Any, str, str]]],
    mutations_fn: Callable[[str, Any], list[tuple[str, str]]],
    max_mutations_per_param: int = MAX_MUTATIONS_PER_PARAM,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """For every candidate endpoint: one baseline request + one request per mutation."""
    results: list[dict[str, Any]] = []
    stats = {"endpoints_probed": 0, "requests_sent": 0, "endpoints_skipped_no_sensitive_param": 0}
    total = len(candidates)

    for idx, ep in enumerate(candidates, start=1):
        sensitive = sensitive_params_fn(ep)
        if not sensitive:
            stats["endpoints_skipped_no_sensitive_param"] += 1
            if on_progress:
                on_progress(endpoints_done=idx, endpoints_total=total, endpoint_id=ep.endpoint_id)
            continue

        baseline_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
        baseline_body_obj = build_body_object(ep)
        baseline_resp = transport.request(
            baseline_probe["method"],
            baseline_probe["url"],
            baseline_probe["headers"],
            (baseline_probe.get("body") or "").encode("utf-8") or None,
        )
        stats["requests_sent"] += 1
        stats["endpoints_probed"] += 1

        for inp, category, _reason in sensitive:
            if inp.in_ == "query":
                original_value = _original_query_value(baseline_probe["url"], inp.name) or inp.sample
            else:
                original_value = baseline_body_obj.get(inp.name, inp.sample)

            muts = mutations_fn(category, original_value)[:max_mutations_per_param]
            for value, description in muts:
                test_probe = dict(baseline_probe)
                if inp.in_ == "query":
                    test_probe["url"] = inject_query(baseline_probe["url"], inp.name, value)
                    test_body = baseline_probe.get("body") or ""
                else:
                    test_body = inject_json_body(
                        baseline_probe.get("body") or "", inp.name, value, baseline=baseline_body_obj
                    )
                    test_probe["body"] = test_body

                test_resp = transport.request(
                    test_probe["method"],
                    test_probe["url"],
                    test_probe["headers"],
                    (test_body or "").encode("utf-8") or None,
                )
                stats["requests_sent"] += 1

                results.append(
                    {
                        "endpoint": ep,
                        "param_in": inp.in_,
                        "param_name": inp.name,
                        "category": category,
                        "payload_value": value,
                        "payload_description": description,
                        "baseline": baseline_resp,
                        "test": test_resp,
                    }
                )

        if on_progress:
            on_progress(
                endpoints_done=idx,
                endpoints_total=total,
                endpoint_id=ep.endpoint_id,
                requests_sent=stats["requests_sent"],
            )

    return results, stats
