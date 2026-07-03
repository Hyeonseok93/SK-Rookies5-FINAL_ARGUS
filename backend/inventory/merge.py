"""Merge endpoint lists from multiple inventory sources."""

from __future__ import annotations

from inventory.schema import ApiTree, Endpoint, HeaderField, InputParam, InventoryMeta

_PLACEHOLDER_SAMPLES = frozenset({"", "argus-test", "test", "null", "undefined"})


def _input_key(inp: InputParam) -> tuple[str, str]:
    return (inp.in_, inp.name)


def _header_key(field: HeaderField) -> str:
    return field.name.lower()


def _is_placeholder_sample(sample: str | None) -> bool:
    if sample is None:
        return True
    return str(sample).strip().lower() in _PLACEHOLDER_SAMPLES


def _should_prefer_sample(
    current_sample: str | None,
    current_sources: list[str],
    incoming_sample: str | None,
    incoming_sources: list[str],
) -> bool:
    if not incoming_sample or _is_placeholder_sample(incoming_sample):
        return False
    if not current_sample or _is_placeholder_sample(current_sample):
        return True
    if "openapi" in incoming_sources and "openapi" not in current_sources:
        return True
    if "probe" in current_sources and "openapi" in incoming_sources:
        return True
    return False


def merge_header_fields(existing: list[HeaderField], new: list[HeaderField]) -> list[HeaderField]:
    by_name: dict[str, HeaderField] = {_header_key(h): h for h in existing}
    for field in new:
        key = _header_key(field)
        if key not in by_name:
            by_name[key] = HeaderField(
                name=field.name,
                sample=field.sample,
                role=field.role,
                required=field.required,
                sources=list(field.sources),
            )
            continue
        cur = by_name[key]
        cur.sources = sorted(set(cur.sources + field.sources))
        if field.sample:
            if not cur.sample:
                cur.sample = field.sample
            elif _should_prefer_sample(cur.sample, cur.sources, field.sample, field.sources):
                cur.sample = field.sample
        if field.required:
            cur.required = True
        if cur.role == "meta" and field.role in ("input", "auth"):
            cur.role = field.role
    return sorted(by_name.values(), key=lambda h: h.name.lower())


def merge_endpoint_headers(
    ep: Endpoint,
    request_headers: list[HeaderField],
    response_headers: list[HeaderField],
) -> None:
    ep.request_headers = merge_header_fields(ep.request_headers, request_headers)
    ep.response_headers = merge_header_fields(ep.response_headers, response_headers)


def merge_inputs(existing: list[InputParam], new: list[InputParam]) -> list[InputParam]:
    by_key: dict[tuple[str, str], InputParam] = {}
    for inp in existing + new:
        key = _input_key(inp)
        if key not in by_key:
            by_key[key] = InputParam(
                in_=inp.in_,
                name=inp.name,
                type=inp.type,
                format=inp.format,
                required=inp.required,
                sample=inp.sample,
                role=inp.role,
                sources=list(inp.sources),
            )
            continue
        cur = by_key[key]
        cur.sources = sorted(set(cur.sources + inp.sources))
        if inp.sample:
            if not cur.sample:
                cur.sample = inp.sample
            elif _should_prefer_sample(cur.sample, cur.sources, inp.sample, inp.sources):
                cur.sample = inp.sample
        if inp.required:
            cur.required = True
        if inp.type and cur.type == "string" and inp.type != "string":
            cur.type = inp.type
        if inp.format and not cur.format:
            cur.format = inp.format
    return sorted(by_key.values(), key=lambda x: (x.in_, x.name))


def merge_endpoints(existing: Endpoint, incoming: Endpoint) -> Endpoint:
    existing.request_params = merge_inputs(existing.request_params, incoming.request_params)
    existing.response_params = merge_inputs(existing.response_params, incoming.response_params)
    existing.request_headers = merge_header_fields(existing.request_headers, incoming.request_headers)
    existing.response_headers = merge_header_fields(existing.response_headers, incoming.response_headers)
    existing.sources = sorted(set(existing.sources + incoming.sources))
    existing.auth = sorted(set(existing.auth + incoming.auth))
    if incoming.kind == "frontend":
        existing.kind = incoming.kind
    return existing


def merge_trees(trees: list[ApiTree], app_name: str = "") -> ApiTree:
    by_id: dict[str, Endpoint] = {}
    sources_used: set[str] = set()
    sources_missing: set[str] = set()

    for tree in trees:
        if tree.meta.sources_used:
            sources_used.update(tree.meta.sources_used)
        if tree.meta.sources_missing:
            sources_missing.update(tree.meta.sources_missing)
        for ep in tree.endpoints:
            eid = ep.endpoint_id
            if eid not in by_id:
                by_id[eid] = ep
            else:
                merge_endpoints(by_id[eid], ep)

    endpoints = sorted(by_id.values(), key=lambda e: (e.base_url, 0 if e.kind == "frontend" else 1, e.path, e.method))

    return ApiTree(
        meta=InventoryMeta(
            app_name=app_name,
            sources_used=sorted(sources_used),
            sources_missing=sorted(sources_missing),
        ),
        endpoints=endpoints,
    )


def restore_reference_samples(target: ApiTree, reference: ApiTree) -> int:
    """Re-apply OpenAPI/ready-tree samples after verify probe enrichment."""
    ref_by_id = {ep.endpoint_id: ep for ep in reference.endpoints}
    restored = 0
    for ep in target.endpoints:
        ref = ref_by_id.get(ep.endpoint_id)
        if ref is None:
            continue
        before = {(p.in_, p.name): p.sample for p in ep.request_params}
        ep.request_params = merge_inputs(ep.request_params, ref.request_params)
        for param in ep.request_params:
            prev = before.get((param.in_, param.name))
            if prev != param.sample and param.sample and not _is_placeholder_sample(param.sample):
                restored += 1
    return restored
