"""Select and deduplicate replayable 2-1 (malicious file upload) findings."""

from __future__ import annotations

from hashlib import sha256
from typing import Any


def finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    evidence = finding_evidence(finding)
    return (
        str(evidence.get("method") or "POST").upper(),
        str(evidence.get("path") or evidence.get("endpoint_id") or ""),
        str(evidence.get("extension") or "").lower(),
        str(evidence.get("technique") or ""),
        str(evidence.get("reason") or ""),
    )


def _rank(finding: dict[str, Any]) -> tuple[int, int, int, int]:
    evidence = finding_evidence(finding)
    severity = str(finding.get("severity") or "").lower()
    reason = str(evidence.get("reason") or "")
    return (
        1 if severity == "high" else 0,
        1 if evidence.get("finding_type") == "true_positive" else 0,
        1 if reason.startswith("disallowed_extension_accepted") else 0,
        1 if reason.startswith("path_exposure") else 0,
    )


def is_replayable(finding: dict[str, Any]) -> bool:
    """Only capture confirmed issues — never the false-positive-candidate
    baseline-rejected notices, which have nothing worth screenshotting."""
    evidence = finding_evidence(finding)
    if evidence.get("rule_id") != "2-1-malicious-upload":
        return False
    finding_type = str(evidence.get("finding_type") or "")
    reason = str(evidence.get("reason") or "")
    if finding_type == "true_positive" and reason.startswith("disallowed_extension_accepted"):
        return True
    if reason.startswith("path_exposure"):
        return True
    return False


def select_representatives(
    findings: list[dict[str, Any]],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        if is_replayable(finding):
            grouped.setdefault(_dedupe_key(finding), []).append(finding)

    selected: list[dict[str, Any]] = []
    for key, rows in grouped.items():
        representative = max(rows, key=_rank)
        evidence = finding_evidence(representative)
        merged = dict(representative)
        merged_evidence = dict(evidence)
        merged_evidence["merged_sources"] = sorted(
            {
                f"{finding_evidence(row).get('engine', 'unknown')}:"
                f"{finding_evidence(row).get('auth_mode', '-')}"
                for row in rows
            }
        )
        merged_evidence["duplicate_count"] = len(rows)
        merged_evidence["dedupe_key"] = list(key)
        merged["evidence"] = merged_evidence
        selected.append(merged)

    return sorted(selected, key=_rank, reverse=True)[:limit]


def stable_finding_id(finding: dict[str, Any]) -> str:
    key = "|".join(_dedupe_key(finding))
    return f"2-1-{sha256(key.encode('utf-8')).hexdigest()[:10]}"
