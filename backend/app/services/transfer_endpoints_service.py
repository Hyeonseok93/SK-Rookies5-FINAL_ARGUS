"""Dashboard-prepared upload/download API endpoints for 2-1 / 2-2."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal
import re
from urllib.parse import parse_qs, urlparse

from diagnosis.replay.normalize import collect_probe_base_urls
from app.services.zap_util import probe_url

TransferKind = Literal["upload", "download"]

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_PATHS: dict[TransferKind, Path] = {
    "upload": DATA_DIR / "upload-endpoints.json",
    "download": DATA_DIR / "download-endpoints.json",
}
_DEFAULT_METHOD: dict[TransferKind, str] = {
    "upload": "POST",
    "download": "GET",
}


def _default_bases(raw_config: dict[str, Any] | None) -> list[str]:
    return collect_probe_base_urls(raw_config)


def resolve_transfer_endpoint_url(raw: str, raw_config: dict[str, Any] | None = None) -> str:
    s = str(raw).strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return probe_url(s.rstrip("/"))
    bases = _default_bases(raw_config)
    if not bases:
        return ""
    base = bases[0].rstrip("/")
    if s.startswith("/"):
        return probe_url(f"{base}{s}")
    return probe_url(f"{base}/{s.lstrip('/')}")


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


def load_transfer_endpoints(kind: TransferKind) -> dict[str, Any]:
    path = _PATHS[kind]
    endpoints: list[dict[str, str]] = []
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("endpoints", []):
            normalized = _normalize_entry(entry, kind=kind)
            if normalized:
                endpoints.append(normalized)
    return {"endpoints": endpoints}


def save_transfer_endpoints(kind: TransferKind, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, str]] = []
    for entry in endpoints:
        item = _normalize_entry(entry, kind=kind)
        if item:
            normalized.append(item)
    payload = {"endpoints": normalized}
    _PATHS[kind].write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_transfer_endpoints(kind)


def dashboard_transfer_entries(
    kind: TransferKind,
    raw_config: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in load_transfer_endpoints(kind).get("endpoints", []):
        raw_url = str(row.get("url") or "").strip()
        if not raw_url:
            continue
        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            parsed = urlparse(raw_url)
            logical_base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        else:
            bases = collect_probe_base_urls(raw_config)
            logical_base = bases[0].rstrip("/") if bases else ""
        resolved = resolve_transfer_endpoint_url(raw_url, raw_config)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        parsed = urlparse(resolved)
        path = parsed.path or "/"
        label = path.rstrip("/").split("/")[-1] or kind
        entries.append(
            {
                "url": resolved,
                "label": label,
                "base_url": logical_base or f"{parsed.scheme}://{parsed.netloc}",
                "path": path,
                "method": str(row.get("method") or _DEFAULT_METHOD[kind]).upper(),
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
):
    """Convert dashboard rows into inventory Endpoint objects for 2-2."""
    from inventory.schema import Endpoint, InputParam

    out: list[Endpoint] = []
    tag = "dashboard-upload" if kind == "upload" else "dashboard-download"
    for row in dashboard_transfer_entries(kind, raw_config):
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
