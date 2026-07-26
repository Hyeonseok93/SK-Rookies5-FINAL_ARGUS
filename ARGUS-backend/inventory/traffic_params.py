"""Parse query/body parameters from observed HTTP traffic."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from inventory.schema import HeaderField, InputParam

GATEWAY_PREFIXES = ("/user-api", "/admin-api")
MULTIPART_NAME_RE = re.compile(
    r'Content-Disposition:\s*form-data;\s*name="([^"]+)"',
    re.IGNORECASE,
)


@dataclass
class TrafficObservation:
    method: str
    url: str
    path: str
    base_url: str
    query_params: dict[str, str] = field(default_factory=dict)
    json_body_fields: dict[str, Any] = field(default_factory=dict)
    form_fields: dict[str, str] = field(default_factory=dict)
    response_json_body_fields: dict[str, Any] = field(default_factory=dict)
    request_header_fields: dict[str, str] = field(default_factory=dict)
    response_header_fields: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    response_content_type: str | None = None
    http_status: int | None = None


AUTH_HEADER_NAMES = frozenset(
    {"authorization", "cookie", "x-auth-token", "x-access-token", "x-api-key"}
)


def header_input_role(name: str) -> str:
    lower = name.lower()
    if lower in AUTH_HEADER_NAMES:
        return "auth"
    if lower.startswith(("x-auth", "x-access", "x-api")) or lower in {"api-key", "apikey"}:
        return "auth"
    if lower == "content-type":
        return "meta"
    return "input"


def build_request_header_block(method: str, url: str, headers: dict[str, str]) -> str:
    """Serialize request headers for traffic parsing."""
    lines = [f"{method.upper()} {url} HTTP/1.1"]
    for name, val in headers.items():
        lines.append(f"{name}: {val}")
    return "\n".join(lines) + "\n"


def parse_request_headers(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (header or "").split("\n"):
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        name = name.strip()
        if name:
            out[name] = val.strip()
    return out


def parse_response_headers(header: str) -> dict[str, str]:
    """Parse response header block (status line + header lines)."""
    lines = (header or "").split("\n")
    if not lines:
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        name = name.strip()
        if name:
            out[name] = val.strip()
    return out


def header_fields_from_mapping(
    headers: dict[str, str],
    *,
    source: str,
    direction: str = "request",
) -> list[HeaderField]:
    fields: list[HeaderField] = []
    for name, sample in headers.items():
        role = "meta" if direction == "response" else header_input_role(name)
        fields.append(
            HeaderField(
                name=name,
                sample=sample if sample else None,
                role=role,
                sources=[source],
            )
        )
    return fields


def headers_from_observation(obs: TrafficObservation, source: str) -> tuple[list[HeaderField], list[HeaderField]]:
    request = header_fields_from_mapping(obs.request_header_fields, source=source, direction="request")
    response = header_fields_from_mapping(obs.response_header_fields, source=source, direction="response")
    return request, response


def normalize_api_path(path: str) -> str:
    p = path or "/"
    for prefix in GATEWAY_PREFIXES:
        if p.startswith(prefix + "/") or p == prefix:
            p = p[len(prefix) :] or "/"
            break
    if not p.startswith("/"):
        p = "/" + p
    return p


def _flatten_json_keys(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, val in obj.items():
            full = f"{prefix}.{key}" if prefix else key
            if isinstance(val, (dict, list)):
                out.update(_flatten_json_keys(val, full))
            else:
                out[full] = val
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        out.update(_flatten_json_keys(obj[0], prefix))
    return out


def parse_query_params(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    raw = parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in raw.items()}


def parse_json_body(body: str) -> dict[str, Any]:
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return _flatten_json_keys(data)


def parse_multipart_body(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in MULTIPART_NAME_RE.finditer(body or ""):
        name = match.group(1)
        if name not in fields:
            fields[name] = ""
    return fields


def parse_request_header(header: str) -> tuple[str, str]:
    lines = (header or "").split("\n")
    if not lines:
        return "GET", ""
    parts = lines[0].strip().split()
    if len(parts) < 2:
        return "GET", ""
    return parts[0].upper(), parts[1]


def content_type_from_header(header: str) -> str | None:
    for line in (header or "").split("\n"):
        if line.lower().startswith("content-type:"):
            return line.split(":", 1)[1].strip().split(";")[0].strip().lower()
    return None


def _json_fields_to_params(fields: dict[str, Any], source: str) -> list[InputParam]:
    inputs: list[InputParam] = []
    for name, sample in fields.items():
        if "." in name:
            continue
        stype = "string"
        if isinstance(sample, bool):
            stype = "boolean"
        elif isinstance(sample, int):
            stype = "integer"
        elif isinstance(sample, float):
            stype = "number"
        inputs.append(
            InputParam(
                in_="body",
                name=name,
                type=stype,
                sample=str(sample) if sample is not None else None,
                sources=[source],
            )
        )
    return inputs


def observation_from_message(
    method: str,
    url: str,
    request_header: str,
    request_body: str,
    *,
    response_header: str | None = None,
    response_body: str | None = None,
) -> TrafficObservation | None:
    if not url or url.startswith("zap:"):
        return None

    req_method = method.upper() if method else parse_request_header(request_header)[0]
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = normalize_api_path(parsed.path or "/")
    ctype = content_type_from_header(request_header)
    req_headers = parse_request_headers(request_header)
    resp_headers = parse_response_headers(response_header or "")
    resp_ctype = content_type_from_header(response_header or "")

    obs = TrafficObservation(
        method=req_method,
        url=url,
        path=path,
        base_url=base,
        query_params=parse_query_params(url),
        content_type=ctype,
        response_content_type=resp_ctype,
        request_header_fields=req_headers,
        response_header_fields=resp_headers,
    )

    body = request_body or ""
    if "multipart/form-data" in (ctype or ""):
        obs.form_fields = parse_multipart_body(body)
    elif ctype and "json" in ctype:
        obs.json_body_fields = parse_json_body(body)
    elif body.strip().startswith(("{", "[")):
        obs.json_body_fields = parse_json_body(body)

    resp_body = response_body or ""
    if resp_ctype and "json" in resp_ctype:
        obs.response_json_body_fields = parse_json_body(resp_body)
    elif resp_body.strip().startswith(("{", "[")):
        obs.response_json_body_fields = parse_json_body(resp_body)

    has_params = (
        obs.query_params
        or obs.json_body_fields
        or obs.form_fields
        or obs.response_json_body_fields
        or obs.request_header_fields
        or obs.response_header_fields
    )
    if not has_params:
        return obs if req_method == "GET" else None
    return obs


def observation_to_request_params(obs: TrafficObservation, source: str = "traffic") -> list[InputParam]:
    """Query / form / request-body fields."""
    inputs: list[InputParam] = []

    for name, sample in obs.query_params.items():
        inputs.append(
            InputParam(
                in_="query",
                name=name,
                type="string",
                sample=str(sample) if sample != "" else None,
                sources=[source],
            )
        )

    for name, sample in obs.form_fields.items():
        inputs.append(
            InputParam(
                in_="form",
                name=name,
                type="string",
                sample=str(sample) if sample != "" else None,
                sources=[source],
            )
        )

    inputs.extend(_json_fields_to_params(obs.json_body_fields, source))
    return inputs


def observation_to_response_params(obs: TrafficObservation, source: str = "traffic") -> list[InputParam]:
    """Response-body fields observed in traffic."""
    return _json_fields_to_params(obs.response_json_body_fields, source)


def observation_to_inputs(obs: TrafficObservation, source: str = "traffic") -> list[InputParam]:
    """Legacy helper — request params only."""
    return observation_to_request_params(obs, source)


def parse_validation_error_fields(body: str) -> list[str]:
    """Extract field names from Spring-style 400/422 JSON errors."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []

    names: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key in ("field", "name", "property", "parameter"):
                if key in node and isinstance(node[key], str):
                    names.append(node[key])
            for val in node.values():
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return names
