"""Dashboard inventory adapters for diagnosis 1-6."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def saved_base_urls(data_dir: Path) -> list[str]:
    raw = _load_json(data_dir / "base-urls.json")
    urls: list[str] = []
    for item in raw.get("urls") or []:
        if isinstance(item, dict) and item.get("url"):
            urls.append(str(item["url"]).rstrip("/"))
    return urls


def login_base_url(data_dir: Path, preferred_target: str | None = None) -> str:
    target_netloc = urlparse(preferred_target or "").netloc
    fallback = ""
    raw = _load_json(data_dir / "login-endpoints.json")
    for row in raw.get("endpoints") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind") or "api") != "api":
            continue
        parsed = urlparse(str(row.get("url") or "").strip())
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if not fallback:
            fallback = base
        if target_netloc and parsed.netloc == target_netloc:
            return base
    return fallback


def inventory_base_urls(data_dir: Path) -> list[str]:
    raw = _load_json(data_dir / "api-tree-verified.json") or _load_json(data_dir / "api-tree-ready.json") or _load_json(data_dir / "api-tree.json")
    urls: list[str] = []
    for ep in raw.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        base = str(ep.get("base_url") or "").rstrip("/")
        kind = str(ep.get("kind") or "")
        if base and kind != "frontend" and base not in urls:
            urls.append(base)
    return urls


def resolve_target(data_dir: Path, raw_config: dict[str, Any], configured: str | None = None) -> str:
    if configured:
        return str(configured).rstrip("/")
    bases = saved_base_urls(data_dir) or inventory_base_urls(data_dir)
    login_base = login_base_url(data_dir)
    if login_base and login_base in bases:
        return login_base
    if login_base:
        return login_base
    api_like_bases = [u for u in bases if not urlparse(u).netloc.endswith(":5173")]
    if api_like_bases:
        return api_like_bases[0].rstrip("/")
    if bases:
        return bases[0].rstrip("/")
    for item in raw_config.get("targets") or []:
        if isinstance(item, dict) and item.get("base_url"):
            return str(item["base_url"]).rstrip("/")
    return "http://localhost:8080"


def latest_openapi_spec(data_dir: Path) -> Path | None:
    try:
        from inventory.load import find_openapi_spec

        found = find_openapi_spec(data_dir)
        if found and found.is_file():
            return found
    except Exception:
        pass

    uploads = data_dir / "uploads"
    if not uploads.is_dir():
        return None
    candidates: list[Path] = []
    for pattern in ("*/openapi.json", "*/openapi.yaml", "*/openapi.yml"):
        candidates.extend(uploads.glob(pattern))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime).resolve()


def login_override(data_dir: Path, target: str) -> dict[str, str]:
    raw = _load_json(data_dir / "login-endpoints.json")
    target_netloc = urlparse(target).netloc
    fallback: dict[str, str] = {}
    for row in raw.get("endpoints") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind") or "api") != "api":
            continue
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        item = {
            "login_target": f"{parsed.scheme}://{parsed.netloc}",
            "login_path": parsed.path or "/",
        }
        if not fallback:
            fallback = item
        if parsed.netloc == target_netloc:
            return item
    return fallback


def _api_tree_candidates(data_dir: Path) -> list[Path]:
    return [
        data_dir / "api-tree-verified.json",
        data_dir / "api-tree-ready.json",
        data_dir / "api-tree.json",
    ]


def latest_api_tree(data_dir: Path) -> tuple[Path | None, dict[str, Any]]:
    for path in _api_tree_candidates(data_dir):
        raw = _load_json(path)
        if isinstance(raw.get("endpoints"), list) and raw.get("endpoints"):
            return path, raw
    return None, {}


def _schema_type(value: Any) -> str:
    raw = str(value or "string").lower()
    if raw in {"int", "integer", "long"}:
        return "integer"
    if raw in {"float", "double", "number", "decimal"}:
        return "number"
    if raw in {"bool", "boolean"}:
        return "boolean"
    if raw in {"array", "list"}:
        return "array"
    if raw in {"object", "dict"}:
        return "object"
    return "string"


def _param_schema(param: dict[str, Any]) -> dict[str, Any]:
    typ = _schema_type(param.get("type"))
    schema: dict[str, Any] = {"type": typ}
    if typ == "array":
        schema["items"] = {"type": "string"}
    sample = param.get("sample")
    if sample not in (None, "") and typ != "array":
        schema["example"] = sample
    return schema


def _endpoint_matches_target(endpoint: dict[str, Any], target: str | None) -> bool:
    if not target:
        return True
    base = str(endpoint.get("base_url") or "").rstrip("/")
    if not base:
        return True
    return urlparse(base).netloc == urlparse(target).netloc


def api_tree_to_openapi_spec(data_dir: Path, target: str | None = None) -> tuple[Path | None, dict[str, Any]]:
    """Build a temporary OpenAPI spec from ARGUS api-tree inventory.

    This is used only when the user did not provide an explicit api_spec.
    It keeps the W16 engine generic because the engine still consumes OpenAPI.
    """
    source_path, tree = latest_api_tree(data_dir)
    if not source_path:
        return None, {"reason": "api_tree_missing"}

    paths: dict[str, Any] = {}
    used = 0
    skipped = 0
    for ep in tree.get("endpoints") or []:
        if not isinstance(ep, dict):
            skipped += 1
            continue
        if str(ep.get("kind") or "api") == "frontend":
            skipped += 1
            continue
        if not _endpoint_matches_target(ep, target):
            skipped += 1
            continue

        method = str(ep.get("method") or "GET").lower()
        if method not in {"get", "post", "put", "patch", "delete", "options", "head"}:
            skipped += 1
            continue
        path = str(ep.get("path") or "").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path

        operation: dict[str, Any] = {
            "summary": ep.get("name") or ep.get("id") or f"{method.upper()} {path}",
            "tags": ep.get("tags") or [],
            "parameters": [],
            "responses": {"default": {"description": "ARGUS api-tree inventory endpoint"}},
            "x-argus-source": "api-tree",
            "x-argus-api-tree-source": str(source_path.name),
        }
        body_props: dict[str, Any] = {}
        required_body: list[str] = []
        for param in ep.get("request_params") or []:
            if not isinstance(param, dict):
                continue
            where = str(param.get("in") or "query").lower()
            name = str(param.get("name") or "").strip()
            if not name:
                continue
            required = bool(param.get("required", False))
            if where == "body":
                body_props[name] = _param_schema(param)
                if required:
                    required_body.append(name)
                continue
            if where not in {"query", "path", "header", "cookie"}:
                where = "query"
            operation["parameters"].append({
                "name": name,
                "in": where,
                "required": True if where == "path" else required,
                "schema": _param_schema(param),
            })
        if body_props:
            schema: dict[str, Any] = {"type": "object", "properties": body_props}
            if required_body:
                schema["required"] = required_body
            operation["requestBody"] = {
                "required": bool(required_body),
                "content": {"application/json": {"schema": schema}},
            }
        paths.setdefault(path, {})[method] = operation
        used += 1

    if used == 0:
        return None, {
            "reason": "api_tree_no_matching_endpoints",
            "source": str(source_path),
            "target": target or "",
            "skipped": skipped,
        }

    out_dir = data_dir / "report" / "1-6"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "api_tree_openapi.generated.json"
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "ARGUS api-tree generated OpenAPI for W16",
            "version": "1.0",
        },
        "servers": [{"url": target.rstrip("/") if target else "/"}],
        "paths": paths,
        "x-argus-generated-from": str(source_path),
        "x-argus-generation-stats": {"used": used, "skipped": skipped},
    }
    out_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path, {
        "source": str(source_path),
        "generated": str(out_path),
        "used": used,
        "skipped": skipped,
        "target": target or "",
    }


def _is_frontend_dev_base(base: str) -> bool:
    netloc = urlparse(base).netloc.lower()
    return netloc.endswith(":5173") or netloc.endswith(":5174")


def preferred_api_tree_base_url(data_dir: Path) -> str:
    _source_path, tree = latest_api_tree(data_dir)
    counts: dict[str, int] = {}
    for ep in tree.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        if str(ep.get("kind") or "api") == "frontend":
            continue
        base = str(ep.get("base_url") or "").rstrip("/")
        if not base:
            continue
        counts[base] = counts.get(base, 0) + 1
    if not counts:
        return ""

    backend_counts = {base: count for base, count in counts.items() if not _is_frontend_dev_base(base)}
    preferred = backend_counts or counts
    login_base = login_base_url(data_dir)
    if login_base and login_base in preferred:
        return login_base
    return max(preferred.items(), key=lambda item: item[1])[0]
