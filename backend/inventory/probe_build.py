"""Build probe HTTP requests for every inventory endpoint (GET/POST/PUT/PATCH/DELETE)."""

from __future__ import annotations

import json
from typing import Any, Callable

from inventory.auth_util import auth_headers, is_auth_header
from inventory.schema import Endpoint, InputParam, build_full_url
from parsers.parse_endpoints import materialize_path_params

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
GATEWAY_PREFIXES = ("/user-api", "/admin-api")

DEFAULT_SEARCH_QUERY: dict[str, str] = {
    "checkIn": "2026-06-28",
    "checkOut": "2026-06-29",
    "guests": "2",
    "page": "0",
    "size": "20",
    "region": "도쿄",
}

DEFAULT_PAGINATION: dict[str, str] = {"page": "0", "size": "20"}


def _is_generic_probe_sample(value: Any) -> bool:
    return str(value).strip() in {"", "1", "test", "sample", "argus"}


def _name_based_sample(inp: InputParam, path: str = "") -> Any | None:
    name = inp.name.lower()
    compact = "".join(ch for ch in name if ch.isalnum())
    lower_path = path.lower()

    if compact == "month":
        return "2026-07"
    if "birth" in compact:
        return "1995-05-25"
    if any(token in compact for token in ("startdate", "checkin", "pickupdate", "departuredate")):
        return "2026-07-01"
    if any(token in compact for token in ("enddate", "checkout", "returndate", "arrivaldate")):
        return "2026-07-10"
    if compact.endswith("date") or compact == "date":
        return "2026-07-01"
    if compact.endswith("time") or compact in {"departuretime", "arrivaltime"}:
        return "2026-07-01T09:00:00"

    if compact == "targettype":
        return "CAR" if "car" in lower_path else "ROOM"
    if compact == "reservationtype":
        if "flight" in lower_path:
            return "FLIGHT"
        if "car" in lower_path:
            return "CAR"
        return "ROOM"
    if compact == "type" and "posts" in lower_path:
        return "PHOTO"
    if compact == "triptype":
        return "ONE_WAY"
    if compact == "seatclass":
        return "ECONOMY"
    if compact == "coveragelevel":
        return "DELUXE"
    if compact == "insurancetype":
        return "BASIC"

    if compact in {"title", "name", "nickname", "insuredname"}:
        return "argus-probe"
    if compact in {"content", "description", "message", "comment"}:
        return "probe"
    if compact == "email":
        return "argus-probe@example.com"
    if "phone" in compact or "tel" in compact:
        return "010-1234-5678"
    if compact == "rating":
        return 5
    if compact in {"usedmileage", "discountamount"}:
        return 0
    if any(token in compact for token in ("amount", "price", "premium", "total")):
        return 10000
    if "passengercount" in compact or compact in {"guests", "capacity", "quantity"}:
        return 2
    return None


def _valid_probe_header_name(name: str) -> bool:
    n = (name or "").strip()
    if not n or " " in n:
        return False
    upper = n.upper()
    return not (upper.startswith("GET ") or upper.startswith("POST ") or upper.startswith("HTTP/"))


def sample_value(inp: InputParam, path: str = "") -> Any:
    heuristic = _name_based_sample(inp, path)
    if heuristic is not None and (inp.sample is None or _is_generic_probe_sample(inp.sample)):
        return heuristic
    if inp.sample is not None:
        if inp.type in ("integer", "int64", "number") and str(inp.sample).isdigit():
            return int(inp.sample)
        if inp.type == "boolean":
            return str(inp.sample).lower() in ("true", "1", "yes")
        return inp.sample
    if heuristic is not None:
        return heuristic
    if inp.type in ("integer", "int64"):
        return 1
    if inp.type == "boolean":
        return False
    if inp.type == "number":
        return 1.0
    return "1"


def frontend_gateway_path(base_url: str, path: str) -> str:
    """Vite dev server proxies API via /user-api or /admin-api."""
    if ":5173" not in base_url:
        return path
    if path.startswith(GATEWAY_PREFIXES):
        return path
    if path.startswith("/api/v1/admin"):
        return f"/admin-api{path}"
    if path.startswith("/api/"):
        return f"/user-api{path}"
    return path


def _heuristic_query(path: str, method: str) -> dict[str, str]:
    if method not in ("GET", "DELETE", "HEAD", "OPTIONS"):
        return {}
    lower = path.lower()
    if "inventory/calendar" in lower:
        return {"month": "2026-07", "targetId": "1", "targetType": "ROOM"}
    if "inventory/check" in lower:
        return {"startDate": "2026-07-01", "endDate": "2026-07-10", "targetId": "1", "targetType": "ROOM"}
    if "search" in lower or ("accommodation" in lower and method == "GET"):
        return dict(DEFAULT_SEARCH_QUERY)
    if method == "GET":
        return dict(DEFAULT_PAGINATION)
    return {}


def _multipart_body(fields: dict[str, str]) -> tuple[str, str]:
    boundary = "----ArgusProbeBoundary7MA4YWxk"
    chunks: list[str] = []
    for name, val in fields.items():
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}\r\n'
        )
    chunks.append(f"--{boundary}--\r\n")
    body = "".join(chunks)
    ctype = f"multipart/form-data; boundary={boundary}"
    return ctype, body


def _heuristic_body(path: str, method: str) -> tuple[str, str] | None:
    if method not in WRITE_METHODS:
        return None
    lower = path.lower()

    if "posts" in lower and method == "POST" and "comment" not in lower:
        return _multipart_body(
            {"title": "argus-probe", "content": "probe", "type": "PHOTO", "rating": ""}
        )

    if "insurance" in lower:
        obj = {
            "productId": 1,
            "insuranceProductId": 1,
            "insuredName": "argus-probe",
            "insuredBirthdate": "1995-05-25",
            "startDate": "2026-07-01",
            "endDate": "2026-07-10",
            "coverageLevel": "DELUXE",
            "totalPremium": 135000,
        }
        return "application/json", json.dumps(obj, ensure_ascii=False)

    if "report/integrated" in lower:
        obj = {
            "memberId": 1,
            "template": "verification",
            "logoUrl": "https://onde.click/assets/logo.png",
        }
        return "application/json", json.dumps(obj, ensure_ascii=False)

    if method == "POST":
        return "application/json", "{}"
    return "application/json", json.dumps({"id": 1}, ensure_ascii=False)


def build_body_object(ep: Endpoint) -> dict[str, Any]:
    """Build JSON body dict — all fields at valid baseline; fuzzing overrides one param only."""
    lower = ep.path.lower()
    if "report/integrated" in lower:
        return {
            "memberId": 1,
            "template": "verification",
            "logoUrl": "https://onde.click/assets/logo.png",
        }

    body_inputs = [i for i in ep.request_params if i.in_ in ("body", "form") and i.role == "input"]
    if body_inputs:
        return {inp.name: sample_value(inp, ep.path) for inp in body_inputs if inp.in_ == "body"}

    guessed = _heuristic_body(ep.path, ep.method.upper())
    if guessed:
        _, body_str = guessed
        try:
            data = json.loads(body_str)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def build_probe_request(
    ep: Endpoint,
    *,
    probe_base_fn: Callable[[str], str] | None = None,
    account_auth: dict[str, Any] | None = None,
    path_param_defaults: dict[str, str] | None = None,
) -> dict[str, Any]:
    rewrite = probe_base_fn or (lambda u: u)
    path = frontend_gateway_path(
        ep.base_url,
        materialize_path_params(ep.path, path_param_defaults),
    )
    method = ep.method.upper()

    query: dict[str, str] = {}
    headers: dict[str, str] = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "ARGUS-Probe/1.0",
        "Connection": "close",
    }

    for inp in ep.request_params:
        if inp.in_ == "query" and inp.role == "input":
            if inp.required or inp.sample is not None:
                query[inp.name] = str(sample_value(inp, ep.path))
        elif inp.in_ == "header" and inp.role in ("input", "auth"):
            if is_auth_header(inp.name):
                continue
            if inp.name.lower() != "content-type" and _valid_probe_header_name(inp.name):
                headers[inp.name] = str(inp.sample or "1")

    for hdr in ep.request_headers:
        if hdr.name.lower() == "content-type":
            continue
        if is_auth_header(hdr.name):
            continue
        if not _valid_probe_header_name(hdr.name):
            continue
        if hdr.role in ("input", "auth") or hdr.sample:
            headers[hdr.name] = str(hdr.sample or "1")

    headers.update(auth_headers(account_auth))

    if not query and method in ("GET", "HEAD", "DELETE", "OPTIONS"):
        query.update(_heuristic_query(ep.path, method))

    body_str = ""
    body_inputs = [i for i in ep.request_params if i.in_ in ("body", "form") and i.role == "input"]

    if method in WRITE_METHODS:
        if body_inputs:
            if any(i.in_ == "form" for i in body_inputs):
                fields = {inp.name: str(sample_value(inp, ep.path)) for inp in body_inputs}
                ctype, body_str = _multipart_body(fields)
                headers["Content-Type"] = ctype
            else:
                obj = {inp.name: sample_value(inp, ep.path) for inp in body_inputs if inp.in_ == "body"}
                body_str = json.dumps(obj, ensure_ascii=False)
                headers["Content-Type"] = "application/json"
        else:
            guessed = _heuristic_body(ep.path, method)
            if guessed:
                ctype, body_str = guessed
                headers["Content-Type"] = ctype

        # Valid fixture overrides generic probe samples (e.g. template "1" → "verification")
        fixture = _heuristic_body(ep.path, method)
        if fixture and body_str and not (body_inputs and fixture[1] == "{}"):
            ctype, body_str = fixture
            headers["Content-Type"] = ctype

    url = build_full_url(rewrite(ep.base_url.rstrip("/")), path, query or None)
    return {"method": method, "url": url, "headers": headers, "body": body_str}


def format_raw_http_request(probe: dict[str, Any]) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(probe["url"])
    host = parsed.netloc
    body = probe.get("body") or ""
    hdrs = dict(probe["headers"])
    if body:
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))

    lines = [f"{probe['method']} {probe['url']} HTTP/1.1", f"Host: {host}"]
    for key, val in hdrs.items():
        if key.lower() != "host":
            lines.append(f"{key}: {val}")
    lines.append("")
    if body:
        return "\r\n".join(lines) + "\r\n" + body
    return "\r\n".join(lines) + "\r\n"
