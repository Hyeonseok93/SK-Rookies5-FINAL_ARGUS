"""api-tree Endpoint를 ARGUS ScanTarget으로 변환"""
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
    schema: dict = {"type": p.type} if p.type else {}
    if p.format:
        schema["format"] = p.format
    return ScanParam(
        name=p.name,
        location=_LOCATION_MAP.get(p.in_, ParamLocation.QUERY),
        required=p.required,
        schema=schema or None,
        sample_value=p.sample,
    )

def endpoint_to_scan_target(ep: Endpoint) -> ScanTarget:
    return ScanTarget(
        method=ep.method.upper(),
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
        key = (target.method, target.base_url, target.path)
        if key not in seen:
            seen[key] = target
            continue
        existing = seen[key]
        existing_keys = {(p.location, p.name) for p in existing.params}
        for param in target.params:
            param_key = (param.location, param.name)
            if param_key not in existing_keys:
                existing.params.append(param)
                existing_keys.add(param_key)
    return list(seen.values())
