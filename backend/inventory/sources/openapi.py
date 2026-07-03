"""Load inventory from OpenAPI 3.x (Swagger) JSON/YAML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta, split_path_query

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _load_spec(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def load_spec_file(path: Path) -> dict[str, Any]:
    return _load_spec(path)


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _schema_type(schema: dict[str, Any]) -> str:
    if not schema:
        return "string"
    if "type" in schema:
        t = schema["type"]
        return t if isinstance(t, str) else "string"
    if "$ref" in schema:
        return "object"
    if "properties" in schema:
        return "object"
    return "string"


def _body_properties(spec: dict[str, Any], operation: dict[str, Any]) -> list[InputParam]:
    inputs: list[InputParam] = []
    rb = operation.get("requestBody") or {}
    content = rb.get("content") or {}
    for mime, media in content.items():
        schema = media.get("schema") or {}
        if "$ref" in schema:
            schema = _resolve_ref(spec, schema["$ref"])
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        for name, prop in props.items():
            if isinstance(prop, dict) and "$ref" in prop:
                prop = _resolve_ref(spec, prop["$ref"])
            inputs.append(
                InputParam(
                    in_="body",
                    name=name,
                    type=_schema_type(prop if isinstance(prop, dict) else {}),
                    format=(prop.get("format") if isinstance(prop, dict) else None),
                    required=name in required,
                    sample=_example_value(prop if isinstance(prop, dict) else {}),
                    sources=["openapi"],
                )
            )
        if mime:
            inputs.append(
                InputParam(
                    in_="header",
                    name="Content-Type",
                    type="string",
                    sample=mime,
                    role="meta",
                    sources=["openapi"],
                )
            )
    return inputs


def _example_value(schema: dict[str, Any]) -> str | None:
    for key in ("example", "default"):
        if key in schema:
            val = schema[key]
            return str(val) if val is not None else None
    return None


def _parameter_inputs(spec: dict[str, Any], operation: dict[str, Any]) -> list[InputParam]:
    inputs: list[InputParam] = []
    params = list(operation.get("parameters") or [])
    path_item = operation.get("_path_item_params") or []
    for param in path_item + params:
        if "$ref" in param:
            param = _resolve_ref(spec, param["$ref"])
        if not isinstance(param, dict):
            continue
        loc = param.get("in")
        name = param.get("name")
        if not loc or not name:
            continue
        if loc not in ("path", "query", "header", "cookie"):
            continue
        in_map = {"path": "path", "query": "query", "header": "header", "cookie": "cookie"}
        schema = param.get("schema") or {}
        if "$ref" in schema:
            schema = _resolve_ref(spec, schema["$ref"])
        role = "auth" if name.lower() in ("authorization", "cookie") else "input"
        if loc == "header" and role != "auth":
            role = "meta" if name.lower() in ("content-type", "accept", "user-agent") else "input"
        # Spring-style query DTOs may be represented as one parameter whose
        # schema references an object.  HTTP sends its properties as separate
        # query parameters, so retain the fields rather than the wrapper name.
        if (
            loc == "query"
            and isinstance(schema, dict)
            and schema.get("type") == "object"
            and schema.get("properties")
        ):
            required_fields = set(schema.get("required") or [])
            for field_name, field_schema in schema["properties"].items():
                if isinstance(field_schema, dict) and "$ref" in field_schema:
                    field_schema = _resolve_ref(spec, field_schema["$ref"])
                resolved_field = field_schema if isinstance(field_schema, dict) else {}
                inputs.append(
                    InputParam(
                        in_="query",
                        name=field_name,
                        type=_schema_type(resolved_field),
                        format=resolved_field.get("format"),
                        required=field_name in required_fields,
                        sample=_example_value(resolved_field),
                        role=role,
                        sources=["openapi"],
                    )
                )
            continue
        inputs.append(
            InputParam(
                in_=in_map[loc],  # type: ignore[arg-type]
                name=name,
                type=_schema_type(schema if isinstance(schema, dict) else {}),
                format=(schema.get("format") if isinstance(schema, dict) else None),
                required=bool(param.get("required", loc == "path")),
                sample=_example_value(schema if isinstance(schema, dict) else {})
                or (_example_value(param) if param.get("example") else None),
                role=role,
                sources=["openapi"],
            )
        )
    return inputs


def _response_properties(spec: dict[str, Any], operation: dict[str, Any]) -> list[InputParam]:
    inputs: list[InputParam] = []
    for code, resp in (operation.get("responses") or {}).items():
        if not str(code).startswith(("2", "default")):
            continue
        if not isinstance(resp, dict):
            continue
        content = resp.get("content") or {}
        for _mime, media in content.items():
            schema = media.get("schema") or {}
            if "$ref" in schema:
                schema = _resolve_ref(spec, schema["$ref"])
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            for name, prop in props.items():
                if isinstance(prop, dict) and "$ref" in prop:
                    prop = _resolve_ref(spec, prop["$ref"])
                inputs.append(
                    InputParam(
                        in_="body",
                        name=name,
                        type=_schema_type(prop if isinstance(prop, dict) else {}),
                        format=(prop.get("format") if isinstance(prop, dict) else None),
                        required=name in required,
                        sample=_example_value(prop if isinstance(prop, dict) else {}),
                        sources=["openapi"],
                    )
                )
    return inputs


def _split_openapi_inputs(raw_inputs: list[InputParam]) -> tuple[list[InputParam], list]:
    from inventory.schema import HeaderField

    request_params: list[InputParam] = []
    request_headers: list[HeaderField] = []
    for inp in raw_inputs:
        if inp.in_ in ("header", "cookie"):
            request_headers.append(
                HeaderField(
                    name=inp.name,
                    sample=inp.sample,
                    role=inp.role if inp.role != "input" else "auth",
                    required=inp.required,
                    sources=list(inp.sources),
                )
            )
        else:
            request_params.append(inp)
    return request_params, request_headers


def request_params_for_operation(spec: dict[str, Any], method: str, path: str) -> list[InputParam]:
    """Request path/query/body params for one operation (for probe enrichment)."""
    path_item = (spec.get("paths") or {}).get(path)
    if not isinstance(path_item, dict):
        return []
    operation = path_item.get(method.lower())
    if not isinstance(operation, dict):
        return []
    operation = dict(operation)
    operation["_path_item_params"] = path_item.get("parameters") or []
    raw = _parameter_inputs(spec, operation)
    raw.extend(_body_properties(spec, operation))
    params, _ = _split_openapi_inputs(raw)
    return [p for p in params if p.in_ in ("path", "query", "body", "form")]


def load_openapi_inventory(
    spec_path: Path,
    base_urls: list[str],
    *,
    spec_base_url: str | None = None,
    source_tag: str | None = None,
) -> ApiTree:
    if not spec_path.is_file():
        return ApiTree(
            meta=InventoryMeta(sources_missing=["openapi"]),
            endpoints=[],
        )

    spec = _load_spec(spec_path)
    paths = spec.get("paths") or {}
    servers = spec.get("servers") or []
    default_base = servers[0].get("url") if servers else None
    if not default_base:
        default_base = spec_base_url
    if not default_base:
        default_base = base_urls[0] if base_urls else "http://localhost"

    # A spec's own server is authoritative. Dashboard/config bases are only a
    # fallback for specs that do not declare servers.
    bases = [str(default_base).rstrip("/")] if servers and default_base else (
        base_urls or [str(default_base).rstrip("/")]
    )
    endpoints: list[Endpoint] = []
    source = f"openapi:{source_tag}" if source_tag else "openapi"

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_only, _ = split_path_query(raw_path)
        path_item_params = path_item.get("parameters") or []

        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not operation:
                continue
            operation = dict(operation)
            operation["_path_item_params"] = path_item_params

            raw_inputs = _parameter_inputs(spec, operation)
            raw_inputs.extend(_body_properties(spec, operation))
            request_params, request_headers = _split_openapi_inputs(raw_inputs)
            response_params = _response_properties(spec, operation)

            for base in bases:
                endpoints.append(
                    Endpoint(
                        method=method.upper(),
                        path=path_only,
                        base_url=base.rstrip("/"),
                        request_params=request_params,
                        response_params=response_params,
                        request_headers=request_headers,
                        sources=[source],
                        kind="api",
                    )
                )

    # Preserve file provenance on parameter/header fields too.
    for endpoint in endpoints:
        for item in endpoint.request_params + endpoint.response_params:
            item.sources = [source if value == "openapi" else value for value in item.sources]
        for header in endpoint.request_headers + endpoint.response_headers:
            header.sources = [source if value == "openapi" else value for value in header.sources]

    return ApiTree(
        meta=InventoryMeta(sources_used=[source] if endpoints else []),
        endpoints=endpoints,
    )
