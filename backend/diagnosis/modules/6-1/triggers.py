"""Generate probe jobs for 6-1 trigger families 1–6."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterator, Literal
from urllib.parse import quote

from inventory.probe_build import WRITE_METHODS, build_probe_request, sample_value
from inventory.schema import Endpoint, InputParam

from parsers.parse_endpoints import materialize_path_params
from payloads import PayloadSpec, utf8_encodable

PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")

TriggerFamily = Literal["param", "body", "path", "method", "header"]

ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


@dataclass(frozen=True)
class ProbeJob:
    family: TriggerFamily
    method: str
    url: str
    headers: dict[str, str]
    body: str | bytes
    trigger_id: str
    param_name: str | None = None
    payload_id: str | None = None
    extra: dict[str, Any] | None = None


def _input_params(ep: Endpoint) -> list[InputParam]:
    return [p for p in ep.request_params if p.role == "input" and p.in_ in ("path", "query", "body", "form")]


def _path_param_names(path: str) -> list[str]:
    return PATH_PARAM_RE.findall(path)


def _default_path_values(ep: Endpoint) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in _path_param_names(ep.path):
        values[name] = "1"
    for inp in ep.request_params:
        if inp.in_ == "path":
            values[inp.name] = str(inp.sample if inp.sample is not None else sample_value(inp))
    return values


def _default_query(ep: Endpoint) -> dict[str, str]:
    query: dict[str, str] = {}
    for inp in ep.request_params:
        if inp.in_ == "query":
            query[inp.name] = str(inp.sample if inp.sample is not None else sample_value(inp))
    return query


def _default_body_obj(ep: Endpoint) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for inp in ep.request_params:
        if inp.in_ == "body":
            obj[inp.name] = sample_value(inp)
    if obj:
        return obj
    base = build_probe_request(ep)
    raw = base.get("body") or ""
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {"argus": "probe"}


def _quote_query_value(value: str) -> str:
    try:
        return quote(value, safe="", encoding="utf-8", errors="strict")
    except UnicodeEncodeError:
        return quote(value, safe="", encoding="utf-8", errors="replace")


def _safe_path_segment(value: str) -> str:
    """Percent-encode path segment values (newlines, spaces, etc.)."""
    try:
        return quote(str(value), safe="", encoding="utf-8", errors="strict")
    except UnicodeEncodeError:
        return quote(str(value), safe="", encoding="utf-8", errors="replace")


def _build_url(ep: Endpoint, path: str, query: dict[str, str]) -> str:
    base = ep.base_url.rstrip("/")
    p = path if path.startswith("/") else f"/{path}"
    url = f"{base}{p}"
    if query:
        qs = "&".join(f"{_quote_query_value(k)}={_quote_query_value(v)}" for k, v in query.items())
        url = f"{url}?{qs}"
    return url


def _safe_json_dumps(obj: dict[str, Any]) -> str | None:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except (UnicodeEncodeError, TypeError, ValueError):
        return None


def iter_param_jobs(ep: Endpoint, payloads: list[PayloadSpec]) -> Iterator[ProbeJob]:
    """Family 1: every input param × every payload (ignore declared type)."""
    path_values = _default_path_values(ep)
    query = _default_query(ep)
    body_obj = _default_body_obj(ep)
    params = _input_params(ep)

    path_names = set(_path_param_names(ep.path))
    if not params and path_names:
        params = [InputParam(in_="path", name=n) for n in path_names]

    if not params:
        for payload in payloads:
            path = materialize_path_params(ep.path, path_values)
            yield ProbeJob(
                family="param",
                method=ep.method.upper(),
                url=_build_url(ep, path, query),
                headers=dict(build_probe_request(ep)["headers"]),
                body=build_probe_request(ep).get("body") or "",
                trigger_id=f"param:none:{payload.payload_id}",
                param_name=None,
                payload_id=payload.payload_id,
            )
        return

    for inp in params:
        for payload in payloads:
            pv = dict(path_values)
            q = dict(query)
            bo = dict(body_obj)
            value: Any = payload.value
            if inp.in_ == "path":
                pv[inp.name] = _safe_path_segment(str(value))
                path = materialize_path_params(ep.path, {k: str(v) for k, v in pv.items()})
            elif inp.in_ == "query":
                q[inp.name] = str(value)
                path = materialize_path_params(ep.path, {k: str(v) for k, v in pv.items()})
            else:
                path = materialize_path_params(ep.path, {k: str(v) for k, v in pv.items()})
                bo[inp.name] = value

            base = build_probe_request(ep, path_param_defaults={k: str(v) for k, v in pv.items()})
            headers = dict(base["headers"])
            body_str = base.get("body") or ""
            if inp.in_ in ("body", "form") and ep.method.upper() in WRITE_METHODS:
                if inp.in_ == "form" or "multipart/form-data" in headers.get("Content-Type", "").lower():
                    body_str = f"--boundary\r\nContent-Disposition: form-data; name=\"{inp.name}\"\r\n\r\n{value}\r\n--boundary--\r\n"
                    headers["Content-Type"] = "multipart/form-data; boundary=boundary"
                else:
                    dumped = _safe_json_dumps(bo)
                    if dumped is None:
                        continue
                    body_str = dumped
                    headers.setdefault("Content-Type", "application/json")

            yield ProbeJob(
                family="param",
                method=ep.method.upper(),
                url=_build_url(ep, path, q),
                headers=headers,
                body=body_str,
                trigger_id=f"param:{inp.in_}:{inp.name}:{payload.payload_id}",
                param_name=inp.name,
                payload_id=payload.payload_id,
                extra={"param_in": inp.in_},
            )


BODY_VARIANTS: list[tuple[str, str, dict[str, str] | None]] = [
    ("empty", "", {"Content-Type": "application/json"}),
    ("brace_only", "{", {"Content-Type": "application/json"}),
    ("truncated_json", '{"a":', {"Content-Type": "application/json"}),
    ("plain_text", "not-json-body-argus", {"Content-Type": "application/json"}),
    ("json_null", "null", {"Content-Type": "application/json"}),
    ("json_array", "[1,2,3]", {"Content-Type": "application/json"}),
    ("json_number", "42", {"Content-Type": "application/json"}),
    ("json_string", '"hello"', {"Content-Type": "application/json"}),
    ("xml_body", "<root><a>1</a></root>", {"Content-Type": "application/xml"}),
    ("form_urlencoded", "a=1&b=2", {"Content-Type": "application/x-www-form-urlencoded"}),
    ("duplicate_keys", '{"a":1,"a":2}', {"Content-Type": "application/json"}),
    ("deep_nest", json.dumps({"a": {"b": {"c": {"d": "x" * 200}}}}), {"Content-Type": "application/json"}),
    ("huge_json", json.dumps({"blob": "X" * 8000}), {"Content-Type": "application/json"}),
    ("utf8_korean", json.dumps({"msg": "한글오류테스트"}), {"Content-Type": "application/json"}),
    ("special_chars", json.dumps({"x": "!@#$%^&*()"}), {"Content-Type": "application/json"}),
    ("type_confusion", json.dumps({"id": "not-a-number", "flag": "maybe"}), {"Content-Type": "application/json"}),
    ("missing_ct", json.dumps({"argus": 1}), None),
    ("wrong_ct_plain", json.dumps({"argus": 1}), {"Content-Type": "text/plain"}),
]


BODY_BYTE_VARIANTS: list[tuple[str, bytes, dict[str, str]]] = [
    ("raw_invalid_utf8", b"\xff\xfe\xfd\x00argus", {"Content-Type": "application/json; charset=utf-8"}),
    ("raw_binary", b"\x00\x01\x02\xff", {"Content-Type": "application/octet-stream"}),
]


def iter_body_jobs(ep: Endpoint) -> Iterator[ProbeJob]:
    """Family 2: malformed / diverse request bodies."""
    if ep.method.upper() not in WRITE_METHODS:
        return
    base = build_probe_request(ep)
    headers_base = dict(base["headers"])

    for variant_id, body, hdr_override in BODY_VARIANTS:
        headers = dict(headers_base)
        if hdr_override:
            headers.update(hdr_override)
        elif "Content-Type" in headers:
            del headers["Content-Type"]
        yield ProbeJob(
            family="body",
            method=ep.method.upper(),
            url=base["url"],
            headers=headers,
            body=body,
            trigger_id=f"body:{variant_id}",
            payload_id=variant_id,
        )

    for variant_id, body, hdr_override in BODY_BYTE_VARIANTS:
        headers = dict(headers_base)
        if hdr_override:
            headers.update(hdr_override)
        yield ProbeJob(
            family="body",
            method=ep.method.upper(),
            url=base["url"],
            headers=headers,
            body=body,
            trigger_id=f"body:{variant_id}",
            payload_id=variant_id,
        )


PATH_VARIANTS = (
    "not_found",
    "double_slash",
    "dot_segment",
    "trailing_garbage",
    "long_segment",
    "invalid_uuid",
)


def iter_path_jobs(ep: Endpoint, payloads: list[PayloadSpec]) -> Iterator[ProbeJob]:
    """Family 3: path manipulation."""
    base_path = materialize_path_params(ep.path, _default_path_values(ep))
    base = build_probe_request(ep)
    method = ep.method.upper()
    headers = dict(base["headers"])
    body = base.get("body") or ""
    query = _default_query(ep)

    token = uuid.uuid4().hex[:12]
    variants: list[tuple[str, str]] = [
        ("not_found", f"/__argus_nf_{token}"),
        ("double_slash", base_path.replace("/", "//", 1)),
        ("dot_segment", f"{base_path}/..%2fargus"),
        ("trailing_garbage", f"{base_path}/{'A' * 400}"),
        ("invalid_uuid", f"{base_path}/00000000-0000-0000-0000-000000000000"),
        ("extra_segment", f"{base_path}/extra/segment/{token}"),
    ]
    for vid, path in variants:
        yield ProbeJob(
            family="path",
            method=method,
            url=_build_url(ep, path, query),
            headers=headers,
            body=body,
            trigger_id=f"path:{vid}",
            payload_id=vid,
        )

    sample_payloads = [p for p in payloads if p.category in ("traversal", "special", "length")][:6]
    for payload in sample_payloads:
        yield ProbeJob(
            family="path",
            method=method,
            url=_build_url(ep, f"{base_path}/{_safe_path_segment(payload.value[:200])}", query),
            headers=headers,
            body=body,
            trigger_id=f"path:payload:{payload.payload_id}",
            payload_id=payload.payload_id,
        )


def iter_method_jobs(ep: Endpoint) -> Iterator[ProbeJob]:
    """Family 4: wrong HTTP methods."""
    base = build_probe_request(ep)
    current = ep.method.upper()
    for method in ALL_METHODS:
        if method == current:
            continue
        yield ProbeJob(
            family="method",
            method=method,
            url=base["url"],
            headers=dict(base["headers"]),
            body=base.get("body") or "",
            trigger_id=f"method:{method}",
            payload_id=method,
        )


HEADER_VARIANTS: list[tuple[str, dict[str, str]]] = [
    ("accept_html", {"Accept": "text/html,application/xhtml+xml"}),
    ("accept_wildcard", {"Accept": "*/*"}),
    ("x_forwarded_for", {"X-Forwarded-For": "127.0.0.1"}),
    ("x_original_url", {"X-Original-URL": "/admin"}),
    ("content_type_xml", {"Content-Type": "application/xml"}),
    ("content_type_text", {"Content-Type": "text/plain"}),
    ("content_type_form", {"Content-Type": "application/x-www-form-urlencoded"}),
    ("no_accept", {}),
]


def iter_header_jobs(ep: Endpoint) -> Iterator[ProbeJob]:
    """Family 6: header tricks (Content-Type mismatch etc.)."""
    base = build_probe_request(ep)
    headers = dict(base["headers"])
    method = ep.method.upper()
    body = base.get("body") or ""

    for variant_id, overrides in HEADER_VARIANTS:
        h = dict(headers)
        if variant_id == "no_accept":
            h.pop("Accept", None)
        else:
            h.update(overrides)
        if method in WRITE_METHODS and variant_id.startswith("content_type") and body:
            pass
        yield ProbeJob(
            family="header",
            method=method,
            url=base["url"],
            headers=h,
            body=body,
            trigger_id=f"header:{variant_id}",
            payload_id=variant_id,
        )

    if method in WRITE_METHODS:
        h = dict(headers)
        h.pop("Content-Type", None)
        yield ProbeJob(
            family="header",
            method=method,
            url=base["url"],
            headers=h,
            body=body or json.dumps({"argus": 1}),
            trigger_id="header:missing_content_type",
            payload_id="missing_content_type",
        )
