"""Dashboard-prepared upload/download API endpoints for 2-1 / 2-2."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal
import re
from urllib.parse import parse_qs, urlparse

from diagnosis.replay.normalize import collect_probe_base_urls
from inventory.probe_build import frontend_gateway_path
from app.services.zap_util import probe_url
from app.workspace import require_data_dir

TransferKind = Literal["upload", "download"]

_DEFAULT_METHOD: dict[TransferKind, str] = {
    "upload": "POST",
    "download": "GET",
}


def _path_for(data_dir: Path, kind: TransferKind) -> Path:
    name = "upload-endpoints.json" if kind == "upload" else "download-endpoints.json"
    return data_dir / name


def _default_bases(raw_config: dict[str, Any] | None) -> list[str]:
    return collect_probe_base_urls(raw_config)


def _logical_transfer_path(raw: str) -> str:
    """Normalize a dashboard transfer path (leading slash only)."""
    path = str(raw or "").strip()
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def _resolved_probe_url(base_url: str, logical_path: str) -> str:
    base = base_url.rstrip("/")
    path = frontend_gateway_path(base, _logical_transfer_path(logical_path))
    return probe_url(f"{base}{path}")


def resolve_transfer_targets(
    raw: str,
    raw_config: dict[str, Any] | None = None,
) -> list[tuple[str, str, str]]:
    """
    Expand a dashboard transfer row to probe targets.

    Returns (base_url, logical_path, resolved_probe_url) per dashboard Base URL.
    Absolute URLs stay a single target; relative paths fan out to every base.
    """
    s = str(raw).strip()
    if not s:
        return []
    if s.startswith("http://") or s.startswith("https://"):
        parsed = urlparse(s)
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        logical = _logical_transfer_path(parsed.path or "/")
        return [(base, logical, _resolved_probe_url(base, logical))]
    logical = _logical_transfer_path(s)
    bases = _default_bases(raw_config)
    if not bases:
        return []
    return [
        (base.rstrip("/"), logical, _resolved_probe_url(base, logical))
        for base in bases
    ]


def resolve_transfer_endpoint_url(raw: str, raw_config: dict[str, Any] | None = None) -> str:
    """First resolved probe URL (backward-compatible helper)."""
    targets = resolve_transfer_targets(raw, raw_config)
    return targets[0][2] if targets else ""


def _normalize_method(raw: str | None, *, kind: TransferKind) -> str:
    method = str(raw or _DEFAULT_METHOD[kind]).strip().upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return _DEFAULT_METHOD[kind]
    return method


def _normalize_entry(raw: dict[str, Any], *, kind: TransferKind) -> dict[str, str] | None:
    url = str(raw.get("url") or "").strip()
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    if not url:
        return None
    return {
        "id": entry_id,
        "url": url,
        "method": _normalize_method(raw.get("method"), kind=kind),
    }


def load_transfer_endpoints(
    kind: TransferKind,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = require_data_dir(data_dir)
    path = _path_for(data_dir, kind)
    endpoints: list[dict[str, str]] = []
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("endpoints", []):
            normalized = _normalize_entry(entry, kind=kind)
            if normalized:
                endpoints.append(normalized)
    return {"endpoints": endpoints}


def save_transfer_endpoints(
    kind: TransferKind,
    endpoints: list[dict[str, Any]],
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = require_data_dir(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, str]] = []
    for entry in endpoints:
        item = _normalize_entry(entry, kind=kind)
        if item:
            normalized.append(item)
    payload = {"endpoints": normalized}
    _path_for(data_dir, kind).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_transfer_endpoints(kind, data_dir)


def dashboard_transfer_entries(
    kind: TransferKind,
    raw_config: dict[str, Any] | None = None,
    data_dir: Path | None = None,
) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in load_transfer_endpoints(kind, data_dir).get("endpoints", []):
        raw_url = str(row.get("url") or "").strip()
        if not raw_url:
            continue
        method = str(row.get("method") or _DEFAULT_METHOD[kind]).upper()
        for base_url, logical_path, resolved in resolve_transfer_targets(raw_url, raw_config):
            if not resolved or resolved in seen:
                continue
            seen.add(resolved)
            label = logical_path.rstrip("/").split("/")[-1] or kind
            entries.append(
                {
                    "url": resolved,
                    "label": label,
                    "base_url": base_url,
                    "path": logical_path,
                    "method": method,
                    "source": "dashboard",
                }
            )
    return entries


def _infer_path_param_samples(template_path: str, resolved_path: str) -> dict[str, str]:
    """Map ``{param}`` placeholders to concrete values from a resolved URL path."""
    tpl = [p for p in template_path.strip("/").split("/") if p]
    res = [p for p in (resolved_path or "").strip("/").split("/") if p]
    if len(tpl) != len(res):
        return {}
    samples: dict[str, str] = {}
    for t_seg, r_seg in zip(tpl, res):
        m = re.fullmatch(r"\{([^}]+)\}", t_seg)
        if m:
            samples[m.group(1)] = r_seg
    return samples


def _download_request_params(row: dict[str, str]) -> list:
    """Build traversal probe params from a resolved download URL (query + path template)."""
    from inventory.schema import InputParam, split_path_query
    from inventory.sources.txt_list import path_template_params

    resolved = row["url"]
    parsed = urlparse(resolved)
    path_only, query_in_path = split_path_query(row["path"])
    resolved_path = parsed.path or path_only

    inputs: list[InputParam] = []
    path_samples = _infer_path_param_samples(path_only, resolved_path)
    for inp in path_template_params(path_only, "dashboard"):
        inputs.append(
            InputParam(
                in_=inp.in_,
                name=inp.name,
                type=inp.type,
                required=inp.required,
                sample=path_samples.get(inp.name),
                role=inp.role,
                sources=inp.sources,
            )
        )

    merged_query: dict[str, str] = dict(query_in_path)
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        merged_query[name] = values[0] if values else ""

    for name, sample in merged_query.items():
        inputs.append(
            InputParam(
                in_="query",
                name=name,
                type="string",
                sample=sample or None,
                required=True,
                sources=["dashboard"],
            )
        )
    return inputs


def dashboard_endpoints_as_inventory(
    kind: TransferKind,
    raw_config: dict[str, Any] | None = None,
    data_dir: Path | None = None,
):
    """Convert dashboard rows into inventory Endpoint objects for 2-2."""
    from inventory.schema import Endpoint, InputParam

    out: list[Endpoint] = []
    tag = "dashboard-upload" if kind == "upload" else "dashboard-download"
    for row in dashboard_transfer_entries(kind, raw_config, data_dir=data_dir):
        if kind == "upload":
            request_params = [
                InputParam(
                    in_="form",
                    name="file",
                    type="string",
                    sources=["dashboard"],
                )
            ]
        else:
            request_params = _download_request_params(row)
        ep_path = row["path"].split("?", 1)[0] or "/"
        out.append(
            Endpoint(
                method=row["method"],
                path=ep_path,
                base_url=row["base_url"],
                request_params=request_params,
                tags=["2-2-candidate", tag],
                sources=["dashboard"],
            )
        )
    return out
