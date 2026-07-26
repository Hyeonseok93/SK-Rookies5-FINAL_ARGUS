"""Select and deduplicate replayable 1-2 findings."""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlsplit


def finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    evidence = finding_evidence(finding)
    raw_url = str(evidence.get("url") or evidence.get("raw_request_url") or "")
    path = urlsplit(raw_url).path.rstrip("/") or "/"
    return (
        str(evidence.get("method") or "GET").upper(),
        path,
        str(evidence.get("param") or evidence.get("parameter") or "").lower(),
        str(evidence.get("injection_type") or "SQL").upper(),
    )


def _looks_like_clean_baseline(finding: dict[str, Any]) -> bool:
    evidence = finding_evidence(finding)
    url = str(evidence.get("url") or "")
    param = str(evidence.get("param") or "")
    values = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    value = values.get(param, "")
    return not bool(re.search(r"(?i)(?:'|\"|--|union|select|sleep\s*\()", value))


def _rank(finding: dict[str, Any]) -> tuple[int, int, int, int]:
    evidence = finding_evidence(finding)
    detail = dict(evidence.get("detail") or {})
    return (
        1 if _looks_like_clean_baseline(finding) else 0,
        1 if detail.get("cross_validated") or evidence.get("engine") == "zap+requests" else 0,
        1 if str(evidence.get("confidence") or "").upper() == "HIGH" else 0,
        1 if str(evidence.get("classification") or "").endswith("ERROR_PATTERN") else 0,
    )


def is_replayable(finding: dict[str, Any]) -> bool:
    evidence = finding_evidence(finding)
    if evidence.get("rule_id") != "G12_INJECTION":
        return False
    if str(evidence.get("verification_status") or "").upper() != "VERIFIED":
        return False
    classification = str(evidence.get("classification") or "").upper()
    confidence = str(evidence.get("confidence") or "").upper()
    if "BOOLEAN" in classification and confidence != "HIGH":
        return False
    if "TIME" in classification:
        return confidence == "HIGH" and "CONFIRMED" in classification
    return "CONFIRMED" in classification


def select_representatives(
    findings: list[dict[str, Any]],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
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
                f"{finding_evidence(row).get('plugin_id', '-')}"
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
    return f"1-2-{sha256(key.encode('utf-8')).hexdigest()[:10]}"
