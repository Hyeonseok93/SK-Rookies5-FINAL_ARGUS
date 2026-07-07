"""ARGUS 1-4 엔진 결과를 팀 표준 DiagnosisFinding으로 변환"""
from __future__ import annotations

from typing import Any

from diagnosis.result import DiagnosisFinding

_CONFIDENCE_TO_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

def confirmed_result_to_finding(
    result: dict[str, Any], confirmed_by_roles: list[str] | None = None
) -> DiagnosisFinding:
    confidence = str(result.get("confidence") or "LOW").upper()
    method = str(result.get("method") or "")
    url = str(result.get("url") or "")
    param = str(result.get("param") or "")
    vuln_type = str(result.get("vuln_type") or "Unknown")
    evidence_text = str(result.get("evidence") or "")
    return DiagnosisFinding(
        severity=_CONFIDENCE_TO_SEVERITY.get(confidence, "low"),
        message=f"{vuln_type} 의심: {method} {url} (param={param}) - {evidence_text}",
        evidence={
            "engine": "argus-1-4",
            "rule_id": result.get("detection_method"),
            "endpoint_id": url,
            "param": param,
            "method": method,
            "vuln_type": vuln_type,
            "risk_level": result.get("risk_level"),
            "confidence": confidence,
            "detection_method": result.get("detection_method"),
            "detection_source": result.get("detection_source"),
            "payload": result.get("payload"),
            "response_status": result.get("status_code", result.get("response_status")),
            "response_time_ms": result.get("response_time_ms"),
            "baseline_status": result.get("baseline_status"),
            "baseline_length": result.get("baseline_length"),
            "payload_response_length": result.get("payload_response_length"),
            "response_body_snippet": result.get("response_body_snippet"),
            "stored_ssrf_probe": result.get("stored_ssrf_probe"),
            "control_probe": result.get("control_probe"),
            "confirmation_rounds": result.get("confirmation_rounds"),
            "baseline_summary": result.get("baseline_summary"),
            "payload_summary": result.get("payload_summary"),
            "confirmed_by_roles": sorted(set(confirmed_by_roles or [])),
        },
    )

def build_findings(merged_findings: list[Any]) -> list[DiagnosisFinding]:
    return [
        confirmed_result_to_finding(r, list(r.get("confirmed_by_roles") or []))
        for r in merged_findings
        if isinstance(r, dict)
    ]

def build_status_and_message(
    findings: list[DiagnosisFinding], *, candidate_count: int, target_count: int
) -> tuple[str, str]:
    high = sum(1 for finding in findings if finding.severity == "high")
    medium = sum(1 for finding in findings if finding.severity == "medium")
    if not target_count:
        return "no_targets", "인벤토리에 스캔 대상이 없습니다 - api-tree를 먼저 빌드하세요"
    if high:
        return "fail", f"1-4 findings: {high} high, {medium} medium ({candidate_count}개 후보 스캔)"
    if medium:
        return "warn", f"1-4 review: {medium}건 medium findings ({candidate_count}개 후보)"
    return "pass", f"1-4 이슈 없음 ({candidate_count}개 후보, {target_count}개 대상 스캔)"
