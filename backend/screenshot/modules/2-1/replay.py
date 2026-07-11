"""Live multipart-upload replay for selected 2-1 findings.

Rebuilds the exact payload bytes the diagnosis scan used (same technique +
extension, via ``diagnosis/modules/2-1/payloads.py``) and re-sends it through
Playwright's HTTP request context so the evidence screenshots show a real,
current request/response instead of the truncated ``body_preview`` stored on
the finding.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from credentials import ReplayCredential
from models import EvidenceCase, HttpExchange
from redaction import redact_headers, redact_text

_MODULE_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _MODULE_DIR.parents[2]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

_BLOCKED_METHODS = {"DELETE", "PATCH"}
_MAX_BODY_CHARS = 4_000


def _load_g21_module(name: str):
    path = _BACKEND_ROOT / "diagnosis" / "modules" / "2-1" / f"{name}.py"
    mod_name = f"g21_capture_{name}"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_payloads_mod = _load_g21_module("payloads")
_multipart_mod = _load_g21_module("multipart")


def display_url(url: str) -> str:
    return str(url or "").replace("host.docker.internal", "localhost")


def replay_allowed(method: str, url: str) -> tuple[bool, str]:
    normalized_method = str(method or "POST").upper()
    if normalized_method in _BLOCKED_METHODS:
        return False, f"{normalized_method} replay is blocked"
    return True, ""


def find_target(
    evidence: dict[str, Any],
    *,
    raw_config: dict[str, Any] | None,
    data_dir: Path,
):
    """Recover file_field/extra_fields/query_params for the finding's endpoint
    the same way the live scan resolved them (config override, else inventory)."""
    targets_mod = _load_g21_module("targets")
    default_allowed = _payloads_mod.normalize_extensions(
        _payloads_mod.load_extension_rules().get("allowed_extensions_default")
    ) or ["jpg", "jpeg", "png", "gif", "webp"]
    targets, _meta = targets_mod.build_upload_targets(
        raw_config, data_dir=data_dir, default_allowed_extensions=default_allowed
    )
    endpoint_id = str(evidence.get("endpoint_id") or "")
    method = str(evidence.get("method") or "POST").upper()
    url = str(evidence.get("url") or "")
    path = str(evidence.get("path") or "")
    for target in targets:
        if endpoint_id and target.endpoint_id == endpoint_id:
            return target
    for target in targets:
        if target.method == method and (target.url == url or target.path == path):
            return target
    return None


def _rebuild_payload(evidence: dict[str, Any]):
    """Regenerate the exact UploadPayload the scan used for this finding."""
    rules = _payloads_mod.load_extension_rules()
    allowed = _payloads_mod.normalize_extensions(rules.get("allowed_extensions_default"))
    all_payloads = _payloads_mod.build_upload_payloads(allowed, rules=rules)
    payload_id = str(evidence.get("payload_id") or "")
    technique = str(evidence.get("technique") or "")
    ext = str(evidence.get("extension") or "").lower()
    for payload in all_payloads:
        if payload_id and payload.payload_id == payload_id:
            return payload
    for payload in all_payloads:
        if payload.technique == technique and payload.ext == ext:
            return payload
    return None


def _rebuild_baseline_payload():
    rules = _payloads_mod.load_extension_rules()
    allowed = _payloads_mod.normalize_extensions(rules.get("allowed_extensions_default"))
    return _payloads_mod.build_baseline_payload(allowed)


def _multipart_exchange(
    *,
    method: str,
    url: str,
    file_field: str,
    filename: str,
    content: bytes,
    content_type: str,
    extra_fields: dict[str, str],
    auth_headers: dict[str, str],
) -> HttpExchange:
    body, mp_content_type = _multipart_mod.encode_multipart(
        file_field=file_field,
        filename=filename,
        file_content=content,
        file_content_type=content_type,
        fields=extra_fields,
    )
    headers = {"Accept": "*/*", "Content-Type": mp_content_type, **auth_headers}
    return HttpExchange(
        method=method,
        url=url,
        display_url=display_url(url),
        request_headers=headers,
        request_body=f"[multipart/form-data body, {len(body)} bytes, filename={filename}]",
        elapsed_ms=None,
    )


def _resolve_auth_headers(
    evidence: dict[str, Any],
    *,
    raw_config: dict[str, Any] | None,
    data_dir: Path,
) -> tuple[dict[str, str], dict[str, Any]]:
    account_email = str(evidence.get("account_email") or "").strip()
    if not account_email:
        return {}, {"ok": False, "reason": "anonymous finding — no login required"}

    from diagnosis.probe_auth import all_account_auths_with_meta, probe_request_headers

    sessions, _meta = all_account_auths_with_meta(raw_config, data_dir=data_dir)
    session = next((s for s in sessions if str(s.get("email") or "") == account_email), None)
    if session is None:
        return {}, {"ok": False, "reason": f"No live session for {account_email}"}
    return probe_request_headers(session), {
        "ok": True,
        "account_id": session.get("id") or account_email,
        "email": account_email,
        "login_label": session.get("login_label"),
    }


def _perform(request_context: Any, exchange: HttpExchange, raw_body: bytes) -> HttpExchange:
    started = time.perf_counter()
    response = request_context.fetch(
        exchange.url,
        method=exchange.method.upper(),
        headers=exchange.request_headers,
        data=raw_body,
        timeout=20_000,
        fail_on_status_code=False,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    body = response.text()[:_MAX_BODY_CHARS]
    return replace(
        exchange,
        display_url=display_url(exchange.url),
        request_headers=redact_headers(exchange.request_headers),
        status_code=response.status,
        response_headers=redact_headers(dict(response.headers)),
        response_body=redact_text(body),
        elapsed_ms=elapsed_ms,
    )


def replay_case(
    case: EvidenceCase,
    *,
    raw_config: dict[str, Any] | None,
    data_dir: Path,
) -> EvidenceCase:
    allowed, reason = replay_allowed(case.baseline.method, case.baseline.url)
    if not allowed:
        raise RuntimeError(reason)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is required for HTTP evidence replay.") from exc

    evidence = dict(case.metadata.get("source_evidence") or {})
    target = find_target(evidence, raw_config=raw_config, data_dir=data_dir)
    extra_fields = dict(target.extra_fields) if target is not None else {}
    file_field = str(target.file_field if target is not None else evidence.get("file_field") or "file")
    method = str(evidence.get("method") or "POST").upper()
    url = str(evidence.get("url") or (target.url if target is not None else ""))

    baseline_payload = _rebuild_baseline_payload()
    attack_payload = _rebuild_payload(evidence)
    if attack_payload is None:
        raise RuntimeError(
            f"Could not rebuild payload for technique={evidence.get('technique')} "
            f"ext={evidence.get('extension')}"
        )

    auth_headers, login_meta = _resolve_auth_headers(evidence, raw_config=raw_config, data_dir=data_dir)

    metadata = dict(case.metadata)
    metadata["login"] = login_meta

    with sync_playwright() as playwright:
        request_context = playwright.request.new_context(ignore_https_errors=True)

        baseline_body, baseline_ct = _multipart_mod.encode_multipart(
            file_field=file_field,
            filename=baseline_payload.filename,
            file_content=baseline_payload.content,
            file_content_type=baseline_payload.content_type,
            fields=extra_fields,
        )
        baseline_exchange = _multipart_exchange(
            method=method,
            url=url,
            file_field=file_field,
            filename=baseline_payload.filename,
            content=baseline_payload.content,
            content_type=baseline_payload.content_type,
            extra_fields=extra_fields,
            auth_headers=auth_headers,
        )
        baseline = _perform(request_context, baseline_exchange, baseline_body)

        attack_body, _attack_ct = _multipart_mod.encode_multipart(
            file_field=file_field,
            filename=attack_payload.filename,
            file_content=attack_payload.content,
            file_content_type=attack_payload.content_type,
            fields=extra_fields,
        )
        attack_exchange = _multipart_exchange(
            method=method,
            url=url,
            file_field=file_field,
            filename=attack_payload.filename,
            content=attack_payload.content,
            content_type=attack_payload.content_type,
            extra_fields=extra_fields,
            auth_headers=auth_headers,
        )
        attack = _perform(request_context, attack_exchange, attack_body)

        request_context.dispose()

    metadata["replay"] = {
        "performed": True,
        "baseline_status": baseline.status_code,
        "attack_status": attack.status_code,
        "baseline_filename": baseline_payload.filename,
        "attack_filename": attack_payload.filename,
        "technique": attack_payload.technique,
        "extension": attack_payload.ext,
    }
    return replace(
        case,
        baseline=baseline,
        attack=attack,
        payload=attack_payload.filename,
        verification_type=attack_payload.technique,
        metadata=metadata,
    )
