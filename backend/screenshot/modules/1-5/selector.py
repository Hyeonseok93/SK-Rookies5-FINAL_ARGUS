"""Select and deduplicate capturable 1-5 findings."""

from __future__ import annotations

from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    return dict(finding.get("evidence") or {})


def resolve_target_url(evidence: dict[str, Any]) -> str:
    """URL to navigate the browser to for this finding's evidence screenshot.

    ``location`` is intentionally excluded here: for redirect findings it's the
    server's ``Location`` response header (the injected sink), not a page of
    the target app, and for reflected findings it's a synthetic
    ``DETECTION_TYPE:payload`` marker — neither is navigable.
    """
    for key in ("test_url", "url", "base_url", "baseline_url", "label"):
        raw = str(evidence.get(key) or "").split("#", 1)[0]
        if not raw:
            continue
        parsed = urlsplit(raw)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return raw
    return ""


def is_capturable(finding: dict[str, Any]) -> bool:
    evidence = finding_evidence(finding)
    rule_id = str(evidence.get("rule_id") or "")
    if not rule_id.startswith("1-5-"):
        return False
    return bool(resolve_target_url(evidence))


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    evidence = finding_evidence(finding)
    rule_id = str(evidence.get("rule_id") or "")
    raw_url = resolve_target_url(evidence)
    path = urlsplit(raw_url).path.rstrip("/") or "/"
    param = str(evidence.get("param_name") or evidence.get("param") or "").lower()
    return (rule_id, path, param)


def _rank(finding: dict[str, Any]) -> tuple[int, int, int]:
    evidence = finding_evidence(finding)
    return (
        _SEVERITY_RANK.get(str(finding.get("severity") or "").lower(), 0),
        1 if evidence.get("confirmed_redirect") else 0,
        1 if evidence.get("stored") else 0,
    )


def select_representatives(
    findings: list[dict[str, Any]],
    *,
    limit: int | None = 8,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        if not is_capturable(finding):
            continue
        key = _dedupe_key(finding)
        current = grouped.get(key)
        if current is None or _rank(finding) > _rank(current):
            grouped[key] = finding

    rows = sorted(grouped.values(), key=_rank, reverse=True)
    return rows if limit is None else rows[:limit]


def stable_finding_id(finding: dict[str, Any]) -> str:
    key = "|".join(_dedupe_key(finding))
    return f"1-5-{sha256(key.encode('utf-8')).hexdigest()[:10]}"
