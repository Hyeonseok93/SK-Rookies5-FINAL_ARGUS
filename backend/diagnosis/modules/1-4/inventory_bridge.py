"""api-tree Endpoint를 ARGUS ScanTarget으로 변환한다."""
from __future__ import annotations

from inventory.schema import Endpoint, InputParam
from app.services.zap_util import probe_url

from models import InputSource, ParamLocation, ScanParam, ScanTarget

_LOCATION_MAP = {
    "query": ParamLocation.QUERY,
    "path": ParamLocation.PATH,
    "body": ParamLocation.BODY,
    "form": ParamLocation.BODY,
    "header": ParamLocation.HEADER,
    "cookie": ParamLocation.HEADER,
}


def _convert_param(p: InputParam) -> ScanParam:
    return ScanParam(
        name=p.name,
        location=_LOCATION_MAP.get(p.in_, ParamLocation.QUERY),
        required=p.required,
        schema={"type": p.type} if p.type else None,
        sample_value=p.sample,
    )


def endpoint_to_scan_target(ep: Endpoint) -> ScanTarget:
    return ScanTarget(
        method=ep.method.upper(),
        # Inventory stores dashboard-facing localhost URLs. Inside the backend
        # container localhost means the ARGUS container itself, so translate
        # it to host.docker.internal before handing targets to requests/ZAP.
        base_url=probe_url(ep.base_url.rstrip("/")),
        path=ep.path if ep.path.startswith("/") else f"/{ep.path}",
        params=[_convert_param(p) for p in ep.request_params],
        tags=list(ep.tags),
        source=InputSource.API_LIST,
        content_type="application/json",
    )


def endpoints_to_scan_targets(endpoints: list[Endpoint]) -> list[ScanTarget]:
    seen: dict[tuple[str, str, str], ScanTarget] = {}
    for ep in endpoints:
        target = endpoint_to_scan_target(ep)
        seen[(target.method, target.base_url, target.path)] = target
    return list(seen.values())
