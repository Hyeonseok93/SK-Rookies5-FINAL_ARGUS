"""Select representative HIGH/MEDIUM 7-4 findings."""

from __future__ import annotations

from hashlib import sha256
from typing import Any


def select_web_groups(findings: list[dict[str, Any]], limit: int = 3) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        if evidence.get("source") not in {"httpx", "zap"}:
            continue
        if str(finding.get("severity") or "").lower() not in {"high", "medium"}:
            continue
        base_url = str(evidence.get("base_url") or evidence.get("url") or "")
        groups.setdefault(base_url, []).append(finding)

    rows = [
        {"base_url": base_url, "findings": items}
        for base_url, items in groups.items()
    ]
    rows.sort(
        key=lambda row: (
            any(str(f.get("severity")).lower() == "high" for f in row["findings"]),
            len(row["findings"]),
        ),
        reverse=True,
    )
    return rows[:limit]


def select_sca(findings: list[dict[str, Any]], limit: int = 3) -> list[dict[str, Any]]:
    rows = []
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        if evidence.get("source") != "sca":
            continue
        if str(finding.get("severity") or "").lower() not in {"high", "medium"}:
            continue
        rows.append(finding)
    rows.sort(
        key=lambda finding: (
            str(finding.get("severity") or "").lower() == "high",
            len((finding.get("evidence") or {}).get("cve_ids") or []),
        ),
        reverse=True,
    )
    return rows[:limit]


def stable_id(prefix: str, value: str) -> str:
    return f"7-4-{prefix}-{sha256(value.encode('utf-8')).hexdigest()[:10]}"

