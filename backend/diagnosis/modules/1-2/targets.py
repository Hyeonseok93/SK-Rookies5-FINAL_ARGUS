"""Build ScanTarget list from verified api-tree (same pattern as 2-2 / 1-5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.services.zap_util import probe_url
from diagnosis.replay.normalize import FRONTEND_PORTS, filter_endpoints_by_probe_bases
from inventory.load import load_api_tree
from inventory.schema import Endpoint, InputParam

from models import InputSource, ParamLocation, ScanParam, ScanTarget

_LOCATION_MAP = {
    "query": ParamLocation.QUERY,
    "path": ParamLocation.PATH,
    "body": ParamLocation.BODY,
    "form": ParamLocation.BODY,
    "header": ParamLocation.HEADER,
    "cookie": ParamLocation.HEADER,
}


def _param_location(param: InputParam) -> ParamLocation:
    return _LOCATION_MAP.get(param.in_, ParamLocation.QUERY)


def _sample_value(param: InputParam) -> str:
    if param.sample is not None and str(param.sample).strip():
        return str(param.sample)
    name = param.name.lower()
    if param.type in ("integer", "number"):
        return "1"
    if param.type == "boolean":
        return "false"
    if name.endswith("id"):
        return "1"
    return "argus-test"


def _is_api_base(base_url: str) -> bool:
    parsed = urlparse(base_url)
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http") == "https" else 80
    return port not in FRONTEND_PORTS


def _endpoint_rank(ep: Endpoint) -> tuple[int, int, int, str]:
    """Prefer API backends (8080/8081) and endpoints that have injectable params."""
    param_count = len(ep.request_params or [])
    return (
        1 if _is_api_base(ep.base_url) else 0,
        1 if param_count > 0 else 0,
        param_count,
        ep.endpoint_id,
    )


def endpoint_to_scan_target(ep: Endpoint) -> ScanTarget:
    params = [
        ScanParam(
            name=p.name,
            location=_param_location(p),
            required=bool(p.required),
            sample_value=_sample_value(p),
        )
        for p in ep.request_params
        if p.role != "meta"
    ]
    probed_base = probe_url(ep.base_url.rstrip("/"))
    return ScanTarget(
        method=ep.method.upper(),
        base_url=probed_base.rstrip("/"),
        path=ep.path if ep.path.startswith("/") else f"/{ep.path}",
        params=params,
        tags=list(ep.tags),
        allowed_roles=list(ep.auth),
        source=InputSource.API_LIST,
        raw=ep.endpoint_id,
        content_type="application/json",
    )


def load_scan_targets(
    data_dir: Path,
    raw_config: dict[str, Any],
    *,
    max_targets: int,
    scan_all: bool,
) -> tuple[list[ScanTarget], dict[str, Any]]:
    tree = load_api_tree(data_dir)
    if tree is None or not tree.endpoints:
        return [], {"error": "no_api_tree"}

    scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw_config)
    if not scoped:
        return [], {
            "error": "no_matching_base_urls",
            "inventory_endpoints": len(tree.endpoints),
        }

    api_eps = [ep for ep in scoped if ep.kind == "api" and _is_api_base(ep.base_url)]
    if not api_eps:
        api_eps = [ep for ep in scoped if ep.kind == "api"]

    ranked = sorted(api_eps, key=_endpoint_rank, reverse=True)
    if not scan_all and max_targets > 0:
        ranked = ranked[:max_targets]

    targets = [endpoint_to_scan_target(ep) for ep in ranked]
    with_params = sum(1 for t in targets if t.params)

    meta = {
        "target_source": "api_tree",
        "inventory_endpoints": len(tree.endpoints),
        "scoped_endpoints": len(scoped),
        "api_backend_endpoints": len(api_eps),
        "scan_targets": len(targets),
        "targets_with_params": with_params,
    }
    return targets, meta
