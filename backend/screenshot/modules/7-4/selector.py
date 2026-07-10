"""Select representative 7-4 findings (all severities; deduped per case)."""

from __future__ import annotations

from hashlib import sha256
from typing import Any


_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def _web_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity") or "").lower(), 0)


def select_web_groups(
    findings: list[dict[str, Any]], limit: int | None = None
) -> list[dict[str, Any]]:
    # A web case is one vulnerability item (check_type), host-agnostic:
    # the same item across multiple hosts is deduped to a single representative.
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        if evidence.get("source") not in {"httpx", "zap"}:
            continue
        check_type = str(evidence.get("check_type") or "")
        groups.setdefault(check_type, []).append(finding)

    rows: list[dict[str, Any]] = []
    for check_type, items in groups.items():
        representative = max(items, key=_web_rank)
        evidence = representative.get("evidence") or {}
        affected_hosts: list[str] = []
        for item in items:
            item_evidence = item.get("evidence") or {}
            host = str(item_evidence.get("base_url") or item_evidence.get("url") or "")
            if host and host not in affected_hosts:
                affected_hosts.append(host)
        rows.append(
            {
                "base_url": str(evidence.get("base_url") or evidence.get("url") or ""),
                "check_type": check_type,
                "findings": [representative],
                "affected_hosts": affected_hosts,
            }
        )
    rows.sort(key=lambda row: _web_rank(row["findings"][0]), reverse=True)
    return rows if limit is None else rows[:limit]


def _sca_rank(finding: dict[str, Any]) -> tuple[bool, int]:
    evidence = finding.get("evidence") or {}
    return (
        str(finding.get("severity") or "").lower() == "high",
        len(evidence.get("cve_ids") or []),
    )


def _sca_library(finding: dict[str, Any]) -> tuple[str, str]:
    """A SCA case is one library release: same groupId + version = same case
    (e.g. netty-codec / netty-handler split across modules)."""
    evidence = finding.get("evidence") or {}
    component = str(evidence.get("component") or "")
    version = str(evidence.get("version") or "")
    group_id = component.rsplit(":", 1)[0] if ":" in component else component
    return (group_id, version)


def select_sca(
    findings: list[dict[str, Any]], limit: int | None = None
) -> list[dict[str, Any]]:
    # Same-case dedup: keep the most significant module per library release.
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        if evidence.get("source") != "sca":
            continue
        key = _sca_library(finding)
        current = groups.get(key)
        if current is None or _sca_rank(finding) > _sca_rank(current):
            groups[key] = finding
    rows = list(groups.values())
    rows.sort(key=_sca_rank, reverse=True)
    return rows if limit is None else rows[:limit]


def stable_id(prefix: str, value: str) -> str:
    return f"7-4-{prefix}-{sha256(value.encode('utf-8')).hexdigest()[:10]}"

