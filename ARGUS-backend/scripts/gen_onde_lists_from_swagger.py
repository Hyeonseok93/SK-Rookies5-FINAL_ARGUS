"""Generate Onde URL/API list files with query params from swagger."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # Zap workspace root
ARGUS = Path(__file__).resolve().parents[2]  # ARGUS_1
SWAGGER = ROOT / "argus" / "swagger.json"
EXAMPLES = ARGUS / "examples"

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Onde_Frontend (WorkStation/Onde) does not read browser URL query strings.
# URL list stays path-only; optional | params remain supported by txt_list parser.
URL_ROUTE_PARAMS: dict[str, list[str]] = {}

# axios query params actually sent by Onde_Frontend (overrides swagger where listed)
ONDE_FRONTEND_API_QUERY: dict[tuple[str, str], list[str]] = {
    ("GET", "/api/v1/accommodations/search"): [
        "region",
        "checkIn",
        "checkOut",
        "guests",
        "page",
        "size",
    ],
    ("GET", "/api/v1/flights/search"): [
        "tripType",
        "departures",
        "arrivals",
        "dates",
        "passengerCount",
        "seatClass",
    ],
    ("GET", "/api/v1/cars/search"): ["location", "pickup", "returnTime", "carType"],
    ("GET", "/api/v1/rental_cars/search"): ["location", "pickup", "returnTime", "carType"],
    ("GET", "/api/v1/properties"): ["swLat", "swLng", "neLat", "neLng"],
    ("GET", "/api/v1/property"): ["swLat", "swLng", "neLat", "neLng"],
    ("GET", "/api/v1/posts"): ["page", "size"],
    ("GET", "/api/v1/auth/check-email"): ["email"],
    ("GET", "/api/v1/auth/check-nickname"): ["nickname"],
}


def _resolve_ref(spec: dict, ref: str) -> dict:
    node: object = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _example_value(schema: dict) -> str | None:
    for key in ("example", "default"):
        val = schema.get(key)
        if val is not None:
            return str(val)
    return None


def _expand_query_param(spec: dict, param: dict) -> list[tuple[str, str | None]]:
    schema = param.get("schema") or {}
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])
    if schema.get("type") == "object" and schema.get("properties"):
        out: list[tuple[str, str | None]] = []
        for name, prop in schema["properties"].items():
            if not isinstance(prop, dict):
                out.append((name, None))
                continue
            if "$ref" in prop:
                prop = _resolve_ref(spec, prop["$ref"])
            out.append((name, _example_value(prop)))
        return out
    name = str(param.get("name", ""))
    if not name:
        return []
    return [(name, param.get("example") or _example_value(schema))]


def swagger_query_params(spec: dict, method: str, path: str) -> list[tuple[str, str | None]] | None:
    paths = spec.get("paths") or {}
    item = paths.get(path)
    if not item:
        return None
    op = item.get(method.lower())
    if not op:
        return None
    merged: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for param in op.get("parameters") or []:
        if param.get("in") != "query":
            continue
        for name, sample in _expand_query_param(spec, param):
            if name in seen:
                continue
            seen.add(name)
            merged.append((name, sample))
    return merged


def _format_pipe(params: list[tuple[str, str | None]], *, names_only: bool = False) -> str:
    if not params:
        return ""
    parts: list[str] = []
    for name, sample in params:
        if names_only or sample is None:
            parts.append(name)
        else:
            parts.append(f"{name}={sample}")
    return " | " + ", ".join(parts)


def _format_pipe_names(names: list[str]) -> str:
    if not names:
        return ""
    return " | " + ", ".join(names)


def _parse_api_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in HTTP_METHODS:
        method, path = parts[0].upper(), parts[1].strip()
    else:
        method, path = "GET", parts[0]
    if not path.startswith("/"):
        path = "/" + path
    path = path.split("|", 1)[0].strip()
    return method, path


def _parse_url_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    return line.split("|", 1)[0].strip()


def generate_api_list(spec: dict, source: Path) -> str:
    out_lines = [
        "# Onde API List — query params from swagger + Onde_Frontend axios overrides",
        "# Format: METHOD /path | param, param",
        "# Path params like {postId} stay in the path. GET query params go after |.",
        "# Search endpoints use params Onde_Frontend actually sends (see gen_onde_lists_from_swagger.py).",
        "# Endpoints missing from swagger are kept without | suffix.",
        "# Merged against API targets in config (:8080 user-api, :8081 admin-api).",
        "",
    ]
    for raw in source.read_text(encoding="utf-8").splitlines():
        parsed = _parse_api_line(raw)
        if parsed is None:
            if raw.strip().startswith("#"):
                continue
            continue
        method, path = parsed
        if method not in {"GET", "HEAD"}:
            out_lines.append(f"{method} {path}")
            continue
        override = ONDE_FRONTEND_API_QUERY.get((method, path))
        if override is not None:
            out_lines.append(f"{method} {path}{_format_pipe_names(override)}")
            continue
        params = swagger_query_params(spec, method, path)
        if params is None:
            out_lines.append(f"{method} {path}")
        else:
            out_lines.append(f"{method} {path}{_format_pipe(params, names_only=True)}")
    return "\n".join(out_lines) + "\n"


def generate_url_list(source: Path) -> str:
    out_lines = [
        "# Onde URL List — frontend SPA routes (Onde_Frontend verified)",
        "# Format: /path   or   /path | param, param  (parser supports optional query)",
        "# Onde does NOT read location.search; routes are path-only.",
        "# Search params belong on API List (backend), not browser URL.",
        "# GET assumed. Uses frontend_base_url from ARGUS config (http://localhost:5173).",
        "",
    ]
    for raw in source.read_text(encoding="utf-8").splitlines():
        path = _parse_url_line(raw)
        if path is None:
            if raw.strip().startswith("#"):
                continue
            continue
        path_only = path.split("?", 1)[0]
        if path_only.startswith("http://") or path_only.startswith("https://"):
            out_lines.append(path_only)
            continue
        if not path_only.startswith("/"):
            path_only = "/" + path_only
        names = URL_ROUTE_PARAMS.get(path_only)
        if names:
            out_lines.append(f"{path_only}{_format_pipe_names(names)}")
        else:
            out_lines.append(path_only)
    return "\n".join(out_lines) + "\n"


def main() -> None:
    spec = json.loads(SWAGGER.read_text(encoding="utf-8"))
    api_src = EXAMPLES / "onde-api-list.txt"
    url_src = EXAMPLES / "onde-url-list.txt"
    api_out = EXAMPLES / "onde-api-list.params.txt"
    url_out = EXAMPLES / "onde-url-list.params.txt"
    api_out.write_text(generate_api_list(spec, api_src), encoding="utf-8")
    url_out.write_text(generate_url_list(url_src), encoding="utf-8")
    print(f"wrote {api_out.name}")
    print(f"wrote {url_out.name}")


if __name__ == "__main__":
    main()
