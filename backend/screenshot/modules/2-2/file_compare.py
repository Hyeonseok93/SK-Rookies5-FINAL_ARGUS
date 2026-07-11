"""Detect download-like responses and build auth vs anon file content comparison."""

from __future__ import annotations

import hashlib
import importlib.util
import re
from pathlib import Path
from typing import Any

from models import HttpExchange

_MAX_PREVIEW_CHARS = 2_400
_FILENAME_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', re.IGNORECASE)


def _load_response_analysis():
    path = Path(__file__).resolve().parents[3] / "diagnosis" / "modules" / "2-2" / "response_analysis.py"
    spec = importlib.util.spec_from_file_location("g22_response_analysis_capture", path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load response_analysis for file compare")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _header(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if key.lower() == wanted:
            return str(value)
    return ""


def _filename(headers: dict[str, str]) -> str:
    disposition = _header(headers, "content-disposition")
    match = _FILENAME_RE.search(disposition)
    if match:
        return match.group(1).strip()
    return ""


def looks_like_download(exchange: HttpExchange) -> bool:
    headers = exchange.response_headers or {}
    ctype = _header(headers, "content-type").lower()
    disposition = _header(headers, "content-disposition").lower()
    raw = exchange.response_body_raw or b""
    if "attachment" in disposition or "filename=" in disposition:
        return True
    if any(token in ctype for token in ("pdf", "octet-stream", "zip", "msword", "spreadsheet", "excel")):
        return True
    if raw.startswith(b"%PDF") or raw[:2] == b"PK":
        return True
    if len(raw) >= 2048 and ("json" not in ctype and "html" not in ctype and "text/" not in ctype):
        return True
    return False


def _preview_text(raw: bytes, headers: dict[str, str]) -> str:
    if not raw:
        return "(empty body)"
    analysis = _load_response_analysis()
    ctype = _header(headers, "content-type").lower()
    if raw.startswith(b"%PDF") or "pdf" in ctype:
        text = analysis.extract_text_for_leak_scan(raw)
        text = (text or "").strip()
        if text:
            return text[:_MAX_PREVIEW_CHARS]
        return f"(PDF binary, {len(raw)} bytes — text extract empty)"
    if raw[:2] == b"PK":
        return f"(ZIP/Office binary, {len(raw)} bytes)"
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw.decode("utf-8", errors="replace")
    printable = sum(1 for ch in decoded[:4000] if ch.isprintable() or ch in "\r\n\t")
    if decoded and printable / max(len(decoded[:4000]), 1) >= 0.8:
        return decoded[:_MAX_PREVIEW_CHARS]
    return f"(binary body, {len(raw)} bytes, sha256={hashlib.sha256(raw).hexdigest()[:16]}…)"


def _side_summary(exchange: HttpExchange, *, label: str) -> dict[str, Any]:
    headers = exchange.response_headers or {}
    raw = exchange.response_body_raw or b""
    sha = hashlib.sha256(raw).hexdigest() if raw else ""
    return {
        "label": label,
        "status": exchange.status_code,
        "content_type": _header(headers, "content-type"),
        "content_disposition": _header(headers, "content-disposition"),
        "filename": _filename(headers),
        "size": len(raw),
        "sha256": sha,
        "sha256_short": sha[:16] if sha else "",
        "preview": _preview_text(raw, headers),
        "is_download": looks_like_download(exchange),
    }


_COMPARE_LABELS = {
    "auth_vs_anon": (
        "Authenticated download",
        "Unauthenticated download",
        "Auth vs Anon",
        "Authenticated File",
        "Unauthenticated File",
    ),
    "baseline_vs_attack": (
        "Baseline response (정상)",
        "Exploit response (공격)",
        "Baseline vs Exploit",
        "Baseline File (정상)",
        "Exploit File (공격)",
    ),
}


def build_file_compare(
    left_exchange: HttpExchange,
    right_exchange: HttpExchange,
    *,
    mode: str = "auth_vs_anon",
) -> dict[str, Any]:
    labels = _COMPARE_LABELS.get(mode) or _COMPARE_LABELS["auth_vs_anon"]
    left_label, right_label, subtitle, left_heading, right_heading = labels
    left = _side_summary(left_exchange, label=left_label)
    right = _side_summary(right_exchange, label=right_label)
    identical = bool(left["sha256"] and left["sha256"] == right["sha256"])
    size_delta = abs(int(left["size"] or 0) - int(right["size"] or 0))
    return {
        "mode": mode,
        "subtitle": subtitle,
        "left_heading": left_heading,
        "right_heading": right_heading,
        "identical": identical,
        "size_delta": size_delta,
        "left": left,
        "right": right,
        # Backward-compatible keys for older manifests / tests.
        "auth": left,
        "anon": right,
        "baseline": left,
        "attack": right,
    }
