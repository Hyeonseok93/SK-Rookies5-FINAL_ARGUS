"""Discover request parameters for dashboard download endpoints (no path hardcoding)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.services.zap_util import probe_url
from inventory.load import find_openapi_specs
from inventory.merge import merge_inputs
from inventory.probe_build import auth_headers, build_full_url, frontend_gateway_path, sample_value
from inventory.schema import ApiTree, Endpoint, InputParam
from inventory.traffic_params import (
    GATEWAY_PREFIXES,
    build_request_header_block,
    normalize_api_path,
    observation_from_message,
    observation_to_request_params,
    parse_validation_error_fields,
)
from parsers.parse_endpoints import materialize_path_params

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _path_match_candidates(path: str) -> list[str]:
    raw = path or "/"
    norm = normalize_api_path(raw)
    out: list[str] = []
    for candidate in (raw, norm):
        if candidate and candidate not in out:
            out.append(candidate)
    if not any(raw.startswith(prefix) for prefix in GATEWAY_PREFIXES):
        for prefix in GATEWAY_PREFIXES:
            joined = f"{prefix}{norm}" if norm.startswith("/") else f"{prefix}/{norm}"
            if joined not in out:
                out.append(joined)
    return out


def _bases_compatible(ep_base: str, ref_base: str) -> bool:
    if not ep_base or not ref_base:
        return True
    from urllib.parse import urlparse

    a = urlparse(ep_base.rstrip("/"))
    b = urlparse(ref_base.rstrip("/"))
    return (a.hostname or "").lower() == (b.hostname or "").lower()


def find_matching_tree_endpoint(ep: Endpoint, tree: ApiTree) -> Endpoint | None:
    """Match dashboard download row to an api-tree endpoint by method + normalized path."""
    want_method = ep.method.upper()
    path_candidates = set(_path_match_candidates(ep.path))
    norm_candidates = {normalize_api_path(p) for p in path_candidates}
    best: Endpoint | None = None
    for row in tree.endpoints:
        if row.method.upper() != want_method:
            continue
        row_norm = normalize_api_path(row.path)
        if row.path not in path_candidates and row_norm not in norm_candidates:
            continue
        if not _bases_compatible(ep.base_url, row.base_url):
            continue
        if best is None or len(row.request_params) > len(best.request_params):
            best = row
    return best


def params_from_openapi_specs(ep: Endpoint, data_dir: Path) -> list[InputParam]:
    from inventory.sources.openapi import _load_spec, request_params_for_operation

    found: list[InputParam] = []
    for spec_path in find_openapi_specs(data_dir):
        spec = _load_spec(spec_path)
        for path in _path_match_candidates(ep.path):
            params = request_params_for_operation(spec, ep.method, path)
            if params:
                found = params
                break
        if found:
            break
    return found


def _merge_params(ep: Endpoint, incoming: list[InputParam]) -> int:
    before = len(ep.request_params)
    ep.request_params = merge_inputs(ep.request_params, incoming)
    return len(ep.request_params) - before


def _has_body_params(ep: Endpoint) -> bool:
    return any(inp.in_ in ("body", "form") for inp in ep.request_params)


def _build_inventory_probe(ep: Endpoint, *, auth: dict[str, Any] | None) -> dict[str, Any]:
    """Build HTTP probe from ep.request_params only — no path-specific body fixtures."""
    path_defaults = {
        inp.name: str(sample_value(inp, ep.path))
        for inp in ep.request_params
        if inp.in_ == "path"
    }
    path = frontend_gateway_path(
        ep.base_url,
        materialize_path_params(ep.path, path_defaults or None),
    )
    method = ep.method.upper()
    query = {
        inp.name: str(sample_value(inp, ep.path))
        for inp in ep.request_params
        if inp.in_ == "query"
    }
    headers: dict[str, str] = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "ARGUS-Probe/1.0",
        "Connection": "close",
    }
    headers.update(auth_headers(auth))
    body_obj = {
        inp.name: sample_value(inp, ep.path)
        for inp in ep.request_params
        if inp.in_ == "body"
    }
    body_str = ""
    if body_obj:
        body_str = json.dumps(body_obj, ensure_ascii=False)
        headers["Content-Type"] = "application/json"
    elif method in WRITE_METHODS:
        body_str = "{}"
        headers["Content-Type"] = "application/json"
    url = build_full_url(probe_url(ep.base_url.rstrip("/")), path, query or None)
    return {"method": method, "url": url, "headers": headers, "body": body_str}


def params_from_probe_message(ep: Endpoint, *, auth: dict[str, Any] | None) -> list[InputParam]:
    """Parse query/body field names from inventory-based probe (no heuristic fixtures)."""
    probe = _build_inventory_probe(ep, auth=auth)
    method = probe["method"]
    url = probe["url"]
    headers = dict(probe.get("headers") or {})
    body = probe.get("body") or ""
    obs = observation_from_message(
        method,
        url,
        build_request_header_block(method, url, headers),
        body,
    )
    if not obs:
        return []
    return observation_to_request_params(obs, "probe_message")


def params_from_live_probe(
    ep: Endpoint,
    transport: Any,
    *,
    auth: dict[str, Any] | None,
) -> list[InputParam]:
    """Hit the download endpoint once and learn body field names from validation errors."""
    probe = _build_inventory_probe(ep, auth=auth)
    headers = dict(probe.get("headers") or {})
    body = probe.get("body") or ""
    body_bytes = body.encode("utf-8") if body else None
    resp = transport.request(
        probe["method"],
        probe["url"],
        headers,
        body_bytes,
        follow_redirects=True,
    )
    if resp.error or resp.status is None:
        return []

    text = resp.body.decode("utf-8", errors="replace")
    names = {name for name in parse_validation_error_fields(text) if name}
    return [
        InputParam(in_="body", name=name, type="string", sources=["live_probe"])
        for name in sorted(names)
    ]


def enrich_download_endpoint_params(
    ep: Endpoint,
    *,
    data_dir: Path | None = None,
    tree: ApiTree | None = None,
    transport: Any | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Fill ep.request_params from api-tree, OpenAPI, then optional live probe.
    Never uses path-specific hardcoded JSON fixtures.
    """
    sources: list[str] = []
    before = len(ep.request_params)

    if tree and tree.endpoints:
        ref = find_matching_tree_endpoint(ep, tree)
        if ref and ref.request_params:
            if _merge_params(ep, ref.request_params) > 0:
                sources.append("api_tree")

    if data_dir is not None and not _has_body_params(ep):
        openapi_params = params_from_openapi_specs(ep, data_dir)
        if openapi_params and _merge_params(ep, openapi_params) > 0:
            sources.append("openapi")

    if ep.request_params:
        probe_params = params_from_probe_message(ep, auth=auth)
        if probe_params and _merge_params(ep, probe_params) > 0:
            sources.append("probe_message")

    if (
        transport is not None
        and ep.method.upper() in WRITE_METHODS
        and not _has_body_params(ep)
    ):
        live_params = params_from_live_probe(ep, transport, auth=auth)
        if live_params and _merge_params(ep, live_params) > 0:
            sources.append("live_probe")

    return {
        "sources": sources,
        "params_before": before,
        "params_after": len(ep.request_params),
        "params_added": len(ep.request_params) - before,
        "body_params": _has_body_params(ep),
    }


def enrich_dashboard_download_endpoints(
    endpoints: list[Endpoint],
    *,
    data_dir: Path | None = None,
    tree: ApiTree | None = None,
    transport: Any | None = None,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for ep in endpoints:
        if "dashboard-download" not in (ep.tags or []):
            continue
        rows.append(enrich_download_endpoint_params(
            ep,
            data_dir=data_dir,
            tree=tree,
            transport=transport,
            auth=auth,
        ))
    return {
        "endpoints": len(rows),
        "with_params": sum(1 for r in rows if r["params_after"] > 0),
        "with_body_params": sum(1 for r in rows if r["body_params"]),
        "details": rows,
    }
