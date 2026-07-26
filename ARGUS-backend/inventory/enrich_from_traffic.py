"""Merge parameters observed in HTTP traffic into endpoint inventory."""

from __future__ import annotations

from inventory.merge import merge_endpoint_headers
from inventory.schema import ApiTree, Endpoint, InputParam
from inventory.traffic_params import (
    TrafficObservation,
    headers_from_observation,
    normalize_api_path,
    observation_to_request_params,
    observation_to_response_params,
    parse_validation_error_fields,
)


def _endpoint_key(method: str, path: str) -> tuple[str, str]:
    return method.upper(), normalize_api_path(path)


def index_endpoints(tree: ApiTree) -> dict[tuple[str, str], list[Endpoint]]:
    idx: dict[tuple[str, str], list[Endpoint]] = {}
    for ep in tree.endpoints:
        key = _endpoint_key(ep.method, ep.path)
        idx.setdefault(key, []).append(ep)
    return idx


def merge_endpoint_params(
    ep: Endpoint,
    *,
    request_params: list[InputParam] | None = None,
    response_params: list[InputParam] | None = None,
) -> None:
    from inventory.merge import merge_endpoints

    merge_endpoints(
        ep,
        Endpoint(
            method=ep.method,
            path=ep.path,
            base_url=ep.base_url,
            request_params=request_params or [],
            response_params=response_params or [],
        ),
    )


def _apply_observation(ep: Endpoint, obs: TrafficObservation, source: str) -> tuple[int, int]:
    req_before = len(ep.request_params)
    resp_before = len(ep.response_params)
    hdr_before = len(ep.request_headers) + len(ep.response_headers)

    merge_endpoint_params(
        ep,
        request_params=observation_to_request_params(obs, source=source),
        response_params=observation_to_response_params(obs, source=source),
    )
    req_hdrs, resp_hdrs = headers_from_observation(obs, source)
    merge_endpoint_headers(ep, req_hdrs, resp_hdrs)

    param_delta = (len(ep.request_params) - req_before) + (len(ep.response_params) - resp_before)
    header_delta = (len(ep.request_headers) + len(ep.response_headers)) - hdr_before
    return param_delta, header_delta


def enrich_tree_from_observations(
    tree: ApiTree,
    observations: list[TrafficObservation],
    *,
    source: str = "traffic",
) -> tuple[ApiTree, int]:
    """Return enriched tree and count of endpoints that gained new params or headers."""
    idx = index_endpoints(tree)
    enriched_count = 0

    for obs in observations:
        key = _endpoint_key(obs.method, obs.path)
        targets = idx.get(key, [])
        if not targets:
            continue
        for ep in targets:
            param_delta, header_delta = _apply_observation(ep, obs, source)
            if param_delta > 0 or header_delta > 0:
                if source not in ep.sources:
                    ep.sources = sorted(set(ep.sources + [source]))
                enriched_count += 1

    return tree, enriched_count


def enrich_from_probe_response(
    ep: Endpoint,
    response_body: str,
    *,
    source: str = "probe",
) -> int:
    """Add request body fields hinted by validation error responses."""
    fields = parse_validation_error_fields(response_body)
    if not fields:
        return 0
    before = len(ep.request_params)
    new_params = [
        InputParam(in_="body", name=name, type="string", sources=[source]) for name in fields
    ]
    merge_endpoint_params(ep, request_params=new_params)
    return len(ep.request_params) - before


def enrich_tree_from_built_probes(
    tree: ApiTree,
    account_auths: list[dict],
    *,
    include_anonymous: bool = True,
    source: str = "zap_probe",
) -> int:
    """Merge request/response params and headers from probe requests sent through ZAP."""
    from app.services.auth_probe_service import auth_passes
    from app.services.zap_util import probe_url
    from inventory.probe_build import build_probe_request
    from inventory.traffic_params import build_request_header_block, observation_from_message

    enriched = 0
    for account_auth, _ in auth_passes(account_auths, include_anonymous=include_anonymous):
        if account_auth is None:
            continue
        for ep in tree.endpoints:
            probe = build_probe_request(
                ep,
                probe_base_fn=probe_url,
                account_auth=account_auth,
            )
            method = probe["method"]
            url = probe["url"]
            headers = dict(probe["headers"])
            body_str = probe.get("body") or ""
            ctype = headers.get("Content-Type", "application/json" if body_str else "")
            if body_str and "Content-Type" not in headers and "content-type" not in headers:
                headers["Content-Type"] = ctype
            fake_header = build_request_header_block(method, url, headers)
            obs = observation_from_message(method, url, fake_header, body_str)
            if not obs:
                continue
            param_delta, header_delta = _apply_observation(ep, obs, source)
            if param_delta > 0 or header_delta > 0:
                if source not in ep.sources:
                    ep.sources = sorted(set(ep.sources + [source]))
                enriched += 1
    return enriched
