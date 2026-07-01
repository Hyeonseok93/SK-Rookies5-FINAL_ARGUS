"""Shared api-tree traversal injection — httpx probes and ZAP send_request fuzz."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any, Literal

from app.services.zap_util import (
    probe_url,
    zap_send_raw_request_full,
)
from diagnosis.result import DiagnosisFinding
from inventory.probe_build import build_body_object, build_probe_request, format_raw_http_request
from inventory.schema import Endpoint
from inventory.tags import PATH_LIKE_NAMES

Classification = Literal["", "path_traversal", "input_validation"]

_DIR = Path(__file__).resolve().parent


def _load_response_analysis():
    spec = importlib.util.spec_from_file_location("diag_g22_response_analysis", _DIR / "response_analysis.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load response_analysis")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ra = _load_response_analysis()

SENSITIVE_BODY_MARKERS = (
    "root:",
    "[extensions]",
    "DB_PASSWORD",
    "APP_KEY",
    "BEGIN RSA PRIVATE KEY",
    "aws_access_key",
    "-----begin",
    "/bin/bash",
    "daemon:",
)
SENSITIVE_PATH_MARKERS = (
    ".env",
    "web.config",
    "application.yml",
    "backup",
    ".git",
    ".htaccess",
    "passwd",
    "shadow",
    "id_rsa",
)
EXPORT_LIKE_PATH = ("export", "download", "report", "attach")
PDF_TEXT_OVERLAP_THRESHOLD = 0.45

TRIGGER_LABELS: dict[str, str] = {
    "payload_target_leak_confirmed": (
        "B: Payload target file content detected in response (e.g. passwd root:, .env secrets)"
    ),
    "sensitive_body_in_response": "B: Response contains sensitive markers (root:, DB_PASSWORD, …)",
    "different_pdf_from_baseline": "B: PDF/binary differs from baseline AND payload-target leak found",
    "different_attachment_from_baseline": "B: Attachment differs and leak markers present",
    "different_content_from_baseline": "B: Response content differs with sensitive/payload leak markers",
    "dynamic_pdf_no_leak": (
        "A: PDF hash differs but extracted text matches baseline — dynamic PDF, no payload leak"
    ),
    "different_pdf_no_payload_leak": (
        "A: PDF differs from baseline but no payload-target sensitive data in extracted text"
    ),
    "different_response_no_payload_leak": "A: Response differs but no payload-target leak detected",
    "identical_response_to_baseline": (
        "A: Malicious payload accepted — response identical to baseline (input validation weakness)"
    ),
    "identical_body_to_baseline": "A: Payload accepted — response body identical to baseline",
    "attachment_without_baseline": "File download response (no baseline to compare)",
    "sensitive_file_ctype": "Content-Type indicates file on sensitive path",
    "sensitive_body": "Response body contains sensitive markers",
    "attachment": "Content-Disposition: attachment",
}


def trigger_label(reason: str) -> str:
    return TRIGGER_LABELS.get(reason, reason)


def body_fingerprint(body: str | bytes) -> dict[str, Any]:
    raw = body if isinstance(body, bytes) else (body or "").encode("utf-8", errors="replace")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def evidence_snippet(headers: dict[str, str], body: str | bytes, *, max_body: int = 120) -> dict[str, str]:
    out: dict[str, str] = {}
    ctype = headers.get("content-type") or headers.get("Content-Type") or ""
    if ctype:
        out["content_type"] = ctype[:200]
    disp = headers.get("content-disposition") or headers.get("Content-Disposition") or ""
    if disp:
        out["content_disposition"] = disp[:200]

    if isinstance(body, bytes):
        preview = body[:max_body]
        if preview.startswith(b"%PDF"):
            return out
        text = preview.decode("utf-8", errors="replace")
    else:
        text = (body or "")[:max_body]
        if text.startswith("%PDF"):
            return out

    stripped = text.replace("\n", " ").strip()
    if stripped and any(c.isalpha() for c in stripped[:40]):
        out["body_preview"] = stripped
    return out


def is_file_like_param(name: str) -> bool:
    return bool(PATH_LIKE_NAMES.search(name or ""))


def file_like_targets(ep: Endpoint) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for inp in ep.request_params:
        if not is_file_like_param(inp.name):
            continue
        if inp.in_ == "query":
            targets.append(("query", inp.name))
        elif inp.in_ in ("body", "form"):
            targets.append(("body", inp.name))
    return targets


def inject_query(url: str, param: str, value: str) -> str:
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    flat = {k: v[0] if v else "" for k, v in qs.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


def inject_json_body(body: str, param: str, value: str, *, baseline: dict[str, Any] | None = None) -> str:
    """Replace only `param`; keep all other baseline fields unchanged."""
    if baseline:
        data = dict(baseline)
    else:
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            return body
    data[param] = value
    return json.dumps(data, ensure_ascii=False)


def build_traversal_probe(
    ep: Endpoint,
    *,
    param_in: str,
    param_name: str,
    payload: str,
    auth: dict[str, Any] | None,
    baseline_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
    base_obj = baseline_body if baseline_body is not None else build_body_object(ep)
    if param_in == "query":
        probe = dict(probe)
        probe["url"] = inject_query(probe["url"], param_name, payload)
    else:
        probe = dict(probe)
        if base_obj:
            probe["body"] = inject_json_body("", param_name, payload, baseline=base_obj)
        else:
            probe["body"] = inject_json_body(probe.get("body") or "", param_name, payload)
    return probe


def has_sensitive_body(body: str) -> bool:
    lower = (body or "")[:12000].lower()
    return any(m.lower() in lower for m in SENSITIVE_BODY_MARKERS)


def has_attachment_disposition(headers: dict[str, str]) -> bool:
    disp = (headers.get("content-disposition") or headers.get("Content-Disposition") or "").lower()
    return "attachment" in disp or "filename=" in disp


def is_pdf_or_binary(body: str | bytes, headers: dict[str, str]) -> bool:
    if isinstance(body, bytes):
        if body.startswith(b"%PDF"):
            return True
    elif (body or "").startswith("%PDF"):
        return True
    ctype = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    return any(t in ctype for t in ("pdf", "octet-stream", "zip", "excel", "spreadsheet"))


def _classify_hash_diff(
    *,
    payload: str,
    baseline_body: str | bytes,
    baseline_headers: dict[str, str],
    payload_body: str | bytes,
    payload_headers: dict[str, str],
) -> tuple[Classification, str, dict[str, Any]]:
    """Hash differs — run text extraction + payload-target leak checks."""
    analysis = _ra.analyze_response_text(payload, baseline_body, payload_body)
    meta: dict[str, Any] = {"analysis": analysis}

    if analysis["payload_leak_markers"]:
        meta["payload_leak_confirmed"] = True
        return "path_traversal", "payload_target_leak_confirmed", meta

    if analysis["generic_sensitive_markers"]:
        meta["sensitive_markers"] = analysis["generic_sensitive_markers"]
        return "path_traversal", "sensitive_body_in_response", meta

    both_pdf = is_pdf_or_binary(payload_body, payload_headers) and is_pdf_or_binary(
        baseline_body, baseline_headers
    )
    if both_pdf:
        overlap = analysis["pdf_text_overlap"]
        if overlap >= PDF_TEXT_OVERLAP_THRESHOLD:
            return "input_validation", "dynamic_pdf_no_leak", meta
        return "input_validation", "different_pdf_no_payload_leak", meta

    if has_attachment_disposition(payload_headers):
        return "input_validation", "different_response_no_payload_leak", meta

    return "input_validation", "different_response_no_payload_leak", meta


def compare_to_baseline(
    *,
    path: str,
    baseline_status: int | None,
    baseline_body: str | bytes,
    baseline_headers: dict[str, str],
    payload_status: int,
    payload_body: str | bytes,
    payload_headers: dict[str, str],
    payload: str = "",
) -> tuple[Classification, str, dict[str, Any]]:
    """
    Classify payload response vs baseline.

    A: payload accepted, same bytes OR different bytes but no payload-target leak in extracted text.
    B: payload-target file content or sensitive markers found in response text.
    """
    meta: dict[str, Any] = {}
    if payload_status < 200 or payload_status >= 400:
        return "", "", meta

    searchable = _ra.extract_text_for_leak_scan(payload_body)
    payload_raw = payload_body if isinstance(payload_body, bytes) else payload_body.encode(
        "utf-8", errors="replace"
    )
    if _ra.find_payload_leak_markers(payload, searchable, raw=payload_raw):
        meta["analysis"] = _ra.analyze_response_text(payload, baseline_body, payload_body)
        meta["payload_leak_confirmed"] = True
        return "path_traversal", "payload_target_leak_confirmed", meta

    if has_sensitive_body(searchable):
        meta["analysis"] = _ra.analyze_response_text(payload, baseline_body, payload_body)
        return "path_traversal", "sensitive_body_in_response", meta

    baseline_ok = baseline_status is not None and 200 <= baseline_status < 400
    if baseline_ok:
        bf = body_fingerprint(baseline_body)
        pf = body_fingerprint(payload_body)
        if pf["size"] > 0 and bf["size"] > 0 and pf["sha256"] == bf["sha256"]:
            return "input_validation", "identical_response_to_baseline", meta

        if pf["size"] > 0 and bf["size"] > 0 and pf["sha256"] != bf["sha256"]:
            return _classify_hash_diff(
                payload=payload,
                baseline_body=baseline_body,
                baseline_headers=baseline_headers,
                payload_body=payload_body,
                payload_headers=payload_headers,
            )

    ctype = (payload_headers.get("content-type") or payload_headers.get("Content-Type") or "").lower()
    if any(t in ctype for t in ("octet-stream", "application/pdf")):
        if any(k in path.lower() for k in SENSITIVE_PATH_MARKERS):
            return "path_traversal", "sensitive_file_ctype", meta

    if has_attachment_disposition(payload_headers):
        return "path_traversal", "attachment_without_baseline", meta

    return "", "", meta


def build_probe_result_evidence(
    *,
    ep: Endpoint,
    param_in: str,
    param_name: str,
    classification: Classification,
    trigger: str,
    primary: dict[str, Any],
    payloads_tried: list[dict[str, Any]],
    baseline_status: int | None,
    baseline_body: str | bytes,
    baseline_headers: dict[str, str] | None,
) -> dict[str, Any]:
    bf = body_fingerprint(baseline_body) if baseline_body else {}
    pf = body_fingerprint(primary.get("body") or "")
    rule_id = "2-2-path-traversal" if classification == "path_traversal" else "2-2-input-validation"
    ev: dict[str, Any] = {
        "rule_id": rule_id,
        "classification": "B" if classification == "path_traversal" else "A",
        "endpoint_id": ep.endpoint_id,
        "method": ep.method,
        "path": ep.path,
        "param": param_name,
        "param_in": param_in,
        "payload": primary.get("payload"),
        "payloads_tried": payloads_tried,
        "payloads_tried_count": len(payloads_tried),
        "http_status": primary.get("http_status"),
        "url": primary.get("url"),
        "trigger": trigger,
        "trigger_label": trigger_label(trigger),
        "baseline_http_status": baseline_status,
        "baseline_sha256": bf.get("sha256"),
        "baseline_size": bf.get("size"),
        "response_sha256": pf.get("sha256"),
        "response_size": pf.get("size"),
        "bodies_identical": (
            bf.get("sha256") == pf.get("sha256") and (bf.get("size") or 0) > 0
        ),
        **evidence_snippet(
            primary.get("headers") or {},
            primary.get("body") or "",
        ),
    }
    if baseline_headers and has_attachment_disposition(baseline_headers):
        ev["baseline_attachment"] = True

    analysis = (primary.get("meta") or {}).get("analysis") or primary.get("analysis")
    if analysis:
        if analysis.get("payload_leak_markers"):
            ev["payload_leak_markers"] = analysis["payload_leak_markers"]
        if analysis.get("generic_sensitive_markers"):
            ev["sensitive_markers"] = analysis["generic_sensitive_markers"]
        if analysis.get("pdf_text_overlap") is not None:
            ev["pdf_text_overlap"] = analysis["pdf_text_overlap"]
        if analysis.get("extracted_text_preview"):
            ev["extracted_text_preview"] = analysis["extracted_text_preview"]
    if primary.get("meta", {}).get("payload_leak_confirmed"):
        ev["payload_leak_confirmed"] = True

    return ev


def response_suspicious(
    path: str,
    status: int,
    body: str,
    headers: dict[str, str],
    *,
    baseline_status: int | None = None,
    baseline_headers: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Forced-browse: no baseline body."""
    cat, trigger, _meta = compare_to_baseline(
        path=path,
        baseline_status=baseline_status,
        baseline_body="",
        baseline_headers=baseline_headers or {},
        payload_status=status,
        payload_body=body,
        payload_headers=headers,
    )
    return cat == "path_traversal", trigger


def _traversal_finding_from_hits(
    ep: Endpoint,
    *,
    param_in: str,
    pname: str,
    path_traversal_hits: list[dict[str, Any]],
    payloads_tried: list[dict[str, Any]],
    baseline_status: int | None,
    baseline_body: bytes,
    baseline_headers: dict[str, str],
) -> DiagnosisFinding:
    def _b_rank(hit: dict[str, Any]) -> int:
        t = hit.get("trigger") or ""
        if t == "payload_target_leak_confirmed":
            p = str(hit.get("payload") or "").lower()
            if "passwd" in p:
                return 0
            return 1
        return 2

    primary = min(path_traversal_hits, key=_b_rank)
    ev = build_probe_result_evidence(
        ep=ep,
        param_in=param_in,
        param_name=pname,
        classification="path_traversal",
        trigger=primary["trigger"],
        primary=primary,
        payloads_tried=payloads_tried,
        baseline_status=baseline_status,
        baseline_body=baseline_body,
        baseline_headers=baseline_headers,
    )
    ev["source"] = "zap"
    ev["engine"] = "zap"
    ev["analysis_mode"] = "hybrid"
    return DiagnosisFinding(
        severity="high",
        message=(
            f"[B] Path traversal (ZAP hybrid) via `{pname}` on {ep.method} {ep.path} "
            f"(HTTP {primary['http_status']}) — response differs from baseline or "
            f"contains sensitive content"
        ),
        evidence=ev,
    )


def run_traversal_probes_via_zap(
    zap: Any,
    candidates: list[Endpoint],
    payloads: list[str],
    *,
    auth: dict[str, Any] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    Hybrid 2-2: send traversal probes through ZAP, classify responses with httpx logic.
    """
    findings: list[DiagnosisFinding] = []
    sent = 0

    for ep in candidates:
        targets = file_like_targets(ep)
        if not targets:
            continue

        baseline_status: int | None = None
        baseline_body: bytes = b""
        baseline_headers: dict[str, str] = {}
        baseline_body_obj = build_body_object(ep)

        baseline_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
        if baseline_body_obj and ep.method.upper() in ("POST", "PUT", "PATCH"):
            baseline_probe = dict(baseline_probe)
            baseline_probe["body"] = json.dumps(baseline_body_obj, ensure_ascii=False)
        baseline_resp = zap_send_raw_request_full(zap, format_raw_http_request(baseline_probe))
        if baseline_resp and baseline_resp.status is not None:
            baseline_status = baseline_resp.status
            baseline_body = baseline_resp.body
            baseline_headers = baseline_resp.headers

        for param_in, pname in targets:
            payloads_tried: list[dict[str, Any]] = []
            path_traversal_hits: list[dict[str, Any]] = []

            for payload in payloads:
                injected = build_traversal_probe(
                    ep,
                    param_in=param_in,
                    param_name=pname,
                    payload=payload,
                    auth=auth,
                    baseline_body=baseline_body_obj,
                )
                raw = format_raw_http_request(injected)
                resp = zap_send_raw_request_full(zap, raw)
                if resp is None or resp.status is None:
                    continue
                sent += 1

                category, trigger, meta = compare_to_baseline(
                    path=ep.path,
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                    baseline_headers=baseline_headers,
                    payload_status=resp.status,
                    payload_body=resp.body,
                    payload_headers=resp.headers,
                    payload=payload,
                )
                pf = body_fingerprint(resp.body)
                entry = {
                    "payload": payload,
                    "category": category or "none",
                    "trigger": trigger,
                    "http_status": resp.status,
                    "sha256": pf["sha256"],
                    "size": pf["size"],
                }
                if meta.get("analysis"):
                    entry["pdf_text_overlap"] = meta["analysis"].get("pdf_text_overlap")
                    if meta["analysis"].get("payload_leak_markers"):
                        entry["payload_leak_markers"] = meta["analysis"]["payload_leak_markers"]
                payloads_tried.append(entry)

                if category == "path_traversal":
                    path_traversal_hits.append(
                        {
                            **entry,
                            "url": injected["url"],
                            "body": resp.body,
                            "headers": resp.headers,
                            "meta": meta,
                        }
                    )

            if path_traversal_hits:
                findings.append(
                    _traversal_finding_from_hits(
                        ep,
                        param_in=param_in,
                        pname=pname,
                        path_traversal_hits=path_traversal_hits,
                        payloads_tried=payloads_tried,
                        baseline_status=baseline_status,
                        baseline_body=baseline_body,
                        baseline_headers=baseline_headers,
                    )
                )

    return findings, {"sent": sent, "hybrid_findings": len(findings)}


def replay_traversal_via_zap(
    zap: Any,
    candidates: list[Endpoint],
    payloads: list[str],
    *,
    auth: dict[str, Any] | None = None,
) -> int:
    _, stats = run_traversal_probes_via_zap(zap, candidates, payloads, auth=auth)
    return int(stats.get("sent", 0))
