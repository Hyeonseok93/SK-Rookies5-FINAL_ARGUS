"""Select representative 2-2 download / traversal findings for evidence capture."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

G22_RULE_IDS = frozenset(
    {
        "2-2-path-traversal",
        "2-2-input-validation",
        "2-2-unauth-download",
        "2-2-forced-browse",
        "2-2-idor",
    }
)


def finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    evidence = finding_evidence(finding)
    return (
        str(evidence.get("rule_id") or ""),
        str(evidence.get("method") or "GET").upper(),
        str(evidence.get("path") or ""),
        str(evidence.get("param") or "").lower(),
        str(evidence.get("payload") or evidence.get("trigger") or ""),
    )


def _rank(finding: dict[str, Any]) -> tuple[int, int, int, int]:
    evidence = finding_evidence(finding)
    severity = str(finding.get("severity") or evidence.get("severity") or "").lower()
    rule_id = str(evidence.get("rule_id") or "")
    trigger = str(evidence.get("trigger") or "")
    return (
        1 if severity == "high" else 0,
        1 if rule_id == "2-2-path-traversal" else 0,
        1 if evidence.get("payload_leak_confirmed") else 0,
        1 if trigger == "payload_target_leak_confirmed" else 0,
    )


def is_capturable(finding: dict[str, Any]) -> bool:
    evidence = finding_evidence(finding)
    rule_id = str(evidence.get("rule_id") or "")
    if rule_id not in G22_RULE_IDS:
        return False
    severity = str(finding.get("severity") or "").lower()
    if severity not in {"medium", "high"}:
        return False
    if rule_id in {"2-2-path-traversal", "2-2-input-validation"}:
        return bool(evidence.get("url") or evidence.get("path"))
    if rule_id == "2-2-unauth-download":
        return bool(evidence.get("path") or evidence.get("url"))
    if rule_id in {"2-2-forced-browse", "2-2-idor"}:
        return bool(evidence.get("url") or evidence.get("path"))
    return False


def select_representatives(
    findings: list[dict[str, Any]],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        if is_capturable(finding):
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
                f"{finding_evidence(row).get('rule_id', '-')}"
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
    return f"2-2-{sha256(key.encode('utf-8')).hexdigest()[:10]}"
