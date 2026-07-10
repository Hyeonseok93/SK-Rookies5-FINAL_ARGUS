"""Fetch and rank GitHub advisories for representative SCA evidence."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import cmp_to_key
from typing import Any

import httpx

_API_URL = "https://api.github.com/advisories/{advisory_id}"
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
_APPLICABILITY_RANK = {"confirmed": 2, "likely": 1, "unconfirmed": 0}


def enrich_advisories(
    advisory_ids: list[str],
    details: list[dict[str, Any]],
    *,
    max_workers: int = 8,
    cache: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return GitHub metadata, retaining deterministic YAML fallbacks."""
    seed_by_id = {
        str(row.get("id")): {
            "advisory_id": str(row.get("id")),
            "severity": str(row.get("severity") or "unknown").lower(),
            "summary": str(row.get("summary") or ""),
        }
        for row in details
        if row.get("id")
    }
    ids = list(dict.fromkeys(str(item) for item in advisory_ids if item))
    rows = [dict(seed_by_id.get(item) or {"advisory_id": item}) for item in ids]
    if not rows:
        return []

    cache = cache if cache is not None else {}
    fetched: dict[str, dict[str, Any]] = {
        row["advisory_id"]: dict(cache[row["advisory_id"]])
        for row in rows
        if cache.get(row["advisory_id"])
    }
    missing_ids = [row["advisory_id"] for row in rows if row["advisory_id"] not in fetched]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(missing_ids) or 1)) as executor:
        futures = {executor.submit(_fetch_one, advisory_id): advisory_id for advisory_id in missing_ids}
        for future in as_completed(futures):
            advisory_id = futures[future]
            try:
                fetched[advisory_id] = future.result()
                cache[advisory_id] = fetched[advisory_id]
            except Exception:
                fetched[advisory_id] = {}

    enriched = []
    for seed in rows:
        metadata = fetched.get(seed["advisory_id"]) or {}
        enriched.append(_normalize({**seed, **metadata}))
    return enriched


def select_representative(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the most applicable and dangerous advisory using stable rules."""
    if not rows:
        return {}
    return sorted(rows, key=cmp_to_key(_compare))[0]


def _fetch_one(advisory_id: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ARGUS-7-4-Evidence",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = httpx.get(_API_URL.format(advisory_id=advisory_id), headers=headers, timeout=12)
    response.raise_for_status()
    payload = response.json()
    cvss = payload.get("cvss_severities") or {}
    v4 = cvss.get("cvss_v4") or {}
    v3 = cvss.get("cvss_v3") or payload.get("cvss") or {}
    selected_cvss = v4 if float(v4.get("score") or 0) > 0 else v3
    vector = str(selected_cvss.get("vector_string") or "")
    references = [str(item) for item in payload.get("references") or []]
    description = str(payload.get("description") or "")
    identifiers = payload.get("identifiers") or []
    cve_id = next(
        (str(row.get("value")) for row in identifiers if row.get("type") == "CVE"),
        str(payload.get("cve_id") or ""),
    )
    epss = payload.get("epss") or {}
    return {
        "advisory_id": advisory_id,
        "cve_id": cve_id,
        "severity": str(payload.get("severity") or "unknown").lower(),
        "summary": str(payload.get("summary") or ""),
        "cvss_version": "4.0" if selected_cvss is v4 else ("3.1" if selected_cvss else ""),
        "cvss_score": float(selected_cvss.get("score") or 0),
        "cvss_vector": vector,
        "epss": float(epss.get("percentage") or 0),
        "remote": "/AV:N" in vector,
        "unauthenticated": "/PR:N" in vector,
        "no_user_interaction": "/UI:N" in vector,
        "no_attack_requirements": "/AT:N" in vector or not vector.startswith("CVSS:4"),
        "public_poc": _has_public_poc(description, references),
        "references": references,
        "vulnerabilities": list(payload.get("vulnerabilities") or []),
        "metadata_available": True,
    }


def _has_public_poc(description: str, references: list[str]) -> bool:
    text = "\n".join([description, *references]).lower()
    return any(marker in text for marker in ("proof of concept", "proof-of-concept", "### poc", "exploit-db"))


def _normalize(row: dict[str, Any]) -> dict[str, Any]:
    row.setdefault("severity", "unknown")
    row.setdefault("summary", "")
    row.setdefault("cve_id", "")
    row.setdefault("cvss_version", "")
    row.setdefault("cvss_score", 0.0)
    row.setdefault("cvss_vector", "")
    row.setdefault("epss", 0.0)
    row.setdefault("remote", False)
    row.setdefault("unauthenticated", False)
    row.setdefault("no_user_interaction", False)
    row.setdefault("no_attack_requirements", False)
    row.setdefault("public_poc", False)
    row.setdefault("vulnerabilities", [])
    row.setdefault("metadata_available", False)
    # The SCA finding itself proves that the installed version matched the advisory range.
    row["installed_version_affected"] = True
    prerequisites = []
    if row["remote"]:
        prerequisites.append("remote")
    if row["unauthenticated"]:
        prerequisites.append("unauthenticated")
    if row["no_user_interaction"]:
        prerequisites.append("no user interaction")
    if row["no_attack_requirements"]:
        prerequisites.append("no CVSS attack requirements")
    row["cvss_prerequisites"] = " / ".join(prerequisites) or "not available"
    # CVSS describes attack characteristics, not whether protocol/application
    # prerequisites (for example HTTP/2) are enabled in this deployment.
    row["operating_conditions"] = "unconfirmed"
    return row


def _compare(left: dict[str, Any], right: dict[str, Any]) -> int:
    """Negative means left is the better representative."""
    left_key = (
        bool(left.get("installed_version_affected")),
        _APPLICABILITY_RANK.get(str(left.get("operating_conditions") or "unconfirmed"), 0),
        _SEVERITY_RANK.get(str(left.get("severity") or "unknown").lower(), 0),
    )
    right_key = (
        bool(right.get("installed_version_affected")),
        _APPLICABILITY_RANK.get(str(right.get("operating_conditions") or "unconfirmed"), 0),
        _SEVERITY_RANK.get(str(right.get("severity") or "unknown").lower(), 0),
    )
    if left_key != right_key:
        return -1 if left_key > right_key else 1

    left_version = str(left.get("cvss_version") or "")
    right_version = str(right.get("cvss_version") or "")
    if left_version and left_version == right_version:
        left_score = float(left.get("cvss_score") or 0)
        right_score = float(right.get("cvss_score") or 0)
        if left_score != right_score:
            return -1 if left_score > right_score else 1

    secondary_left = (
        float(left.get("epss") or 0),
        bool(left.get("public_poc")),
        bool(left.get("remote")),
        bool(left.get("unauthenticated")),
    )
    secondary_right = (
        float(right.get("epss") or 0),
        bool(right.get("public_poc")),
        bool(right.get("remote")),
        bool(right.get("unauthenticated")),
    )
    if secondary_left != secondary_right:
        return -1 if secondary_left > secondary_right else 1

    left_id = str(left.get("advisory_id") or "")
    right_id = str(right.get("advisory_id") or "")
    return -1 if left_id < right_id else (1 if left_id > right_id else 0)
