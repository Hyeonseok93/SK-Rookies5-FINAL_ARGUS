"""Convert embedded W16 findings into ARGUS diagnosis findings."""

from __future__ import annotations

from typing import Any

from diagnosis.result import DiagnosisFinding


def severity(raw: dict[str, Any]) -> str:
    cls = raw.get("classification") or {}
    final_status = str(cls.get("final_status") or "").lower()
    cls_confidence = str(cls.get("confidence") or "").lower()
    review_bucket = str(raw.get("review_bucket") or "").lower()

    if final_status == "not_vulnerable" or review_bucket == "noise":
        return "info"

    # A raw HTTP risk label (CRITICAL/HIGH) reflects "the fuzzer sent an attack
    # payload and got a 5xx", not that the finding was actually validated. The
    # engine's own classification (final_status/confidence) and the
    # baseline-comparison review_bucket carry the real signal, so severity is
    # derived from those instead of blindly trusting raw["risk"].
    if final_status == "vulnerable" and cls_confidence == "high" and review_bucket == "report_candidate":
        return "high"
    if final_status == "vulnerable":
        return "medium"
    if final_status == "potential_vulnerable" and review_bucket == "report_candidate":
        return "medium"
    if final_status == "potential_vulnerable":
        return "low"
    return "info"


def finding_message(raw: dict[str, Any]) -> str:
    cls = raw.get("classification") or {}
    resp = raw.get("response_analysis") or {}
    vuln_type = cls.get("vuln_type") or "input_validation_exception_handling"
    exception_type = resp.get("exception_type") or "server_error"
    url = raw.get("normalized_url") or raw.get("url") or ""
    return f"1-6 {vuln_type}: {exception_type} at {url}"


_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _vuln_type_key(raw: dict[str, Any]) -> str:
    """Best-available vulnerability category, used to keep one representative
    finding per type instead of every near-duplicate occurrence (same payload
    hitting different endpoints/roles)."""
    kisa = str(raw.get("kisa_code") or "").strip()
    if kisa:
        return f"kisa:{kisa}"
    cwe = raw.get("cwe_id") or next(iter(raw.get("cwe") or []), None)
    if cwe:
        return f"cwe:{cwe}"
    owasp = str(raw.get("owasp_id") or raw.get("owasp") or "").strip()
    if owasp:
        return f"owasp:{owasp}"
    payload = str(raw.get("payload_name") or "").strip()
    if payload:
        return f"payload:{payload}"
    return f"vector:{raw.get('attack_vector') or 'unknown'}"


def _clean_reproduction_flow(steps: Any) -> list[dict[str, Any]]:
    if not isinstance(steps, list):
        return []
    out: list[dict[str, Any]] = []
    for s in steps:
        if not isinstance(s, dict):
            continue
        out.append(
            {
                "step": s.get("step"),
                "label": s.get("label"),
                "highlight": s.get("highlight"),
                "rel_path": s.get("rel_path"),
            }
        )
    return out


def convert_findings(raw_findings: list[dict[str, Any]], limit: int) -> list[DiagnosisFinding]:
    """
    한 유형(kisa/cwe/owasp/payload)당 가장 심각한 대표 finding 하나만 리포트에
    올린다 — 같은 취약점이 여러 엔드포인트/역할에서 반복 발견돼도 리포트엔
    중복 없이 유형별 1건 + 실제 발견 횟수(type_occurrences)로 표시.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        cls = raw.get("classification") or {}
        if cls.get("final_status") == "not_vulnerable":
            continue
        if str(raw.get("review_bucket") or "").lower() == "noise":
            continue
        grouped.setdefault(_vuln_type_key(raw), []).append(raw)

    representatives: list[tuple[dict[str, Any], int]] = []
    for group in grouped.values():
        best = max(group, key=lambda r: _SEVERITY_ORDER.get(severity(r), 0))
        representatives.append((best, len(group)))

    representatives.sort(key=lambda row: -_SEVERITY_ORDER.get(severity(row[0]), 0))

    out: list[DiagnosisFinding] = []
    for raw, occurrences in representatives:
        cls = raw.get("classification") or {}
        out.append(
            DiagnosisFinding(
                severity=severity(raw),
                message=finding_message(raw),
                evidence={
                    "rule_id": "1-6-input-validation",
                    "source": raw.get("source"),
                    "role": raw.get("role"),
                    "url": raw.get("url"),
                    "normalized_url": raw.get("normalized_url"),
                    "payload_name": raw.get("payload_name"),
                    "attack_vector": raw.get("attack_vector"),
                    "status_code": raw.get("status_code"),
                    "elapsed_sec": raw.get("elapsed_sec"),
                    "classification": cls,
                    "response_analysis": raw.get("response_analysis"),
                    "evidence_reason": raw.get("evidence_reason"),
                    "response_text_snippet": raw.get("response_text_snippet"),
                    "screenshot_rel_path": raw.get("screenshot_rel_path"),
                    "overlay_applied": raw.get("overlay_applied"),
                    "reproduction_flow": _clean_reproduction_flow(raw.get("reproduction_flow")),
                    "type_occurrences": occurrences,
                },
            )
        )
        if limit and len(out) >= limit:
            break
    return out


def report_status(findings: list[DiagnosisFinding]) -> str:
    if any(f.severity == "high" for f in findings):
        return "fail"
    if any(f.severity in {"medium", "low"} for f in findings):
        return "warn"
    return "pass"