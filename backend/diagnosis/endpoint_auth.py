"""Classify endpoints by cookie/auth requirement from Verify probe results.

Shared by 4-1 (cookie cross/tamper), 2-2 (auth-aware probes), and inventory UI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.services.auth_probe_service import (
    account_access_allowed,
    account_access_for_endpoint,
    infer_endpoint_auth_labels,
)

AuthRequirement = Literal["auth_required", "public", "optional_auth", "unknown"]

VERIFY_REPORT_NAME = "verify-report.json"


@dataclass(frozen=True)
class EndpointAuthClass:
    endpoint_id: str
    requirement: AuthRequirement
    anonymous_status: int | None
    authenticated_ok: bool
    labels: tuple[str, ...]

    def cookie_probe_relevant(self) -> bool:
        """True when swapping/tampering cookies can meaningfully indicate a flaw."""
        return self.requirement == "auth_required"

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "requirement": self.requirement,
            "anonymous_status": self.anonymous_status,
            "authenticated_ok": self.authenticated_ok,
            "labels": list(self.labels),
            "cookie_probe_relevant": self.cookie_probe_relevant(),
        }


def _anonymous_status(rows: list[dict[str, Any]]) -> int | None:
    for row in rows:
        if str(row.get("auth_mode") or "anonymous") == "anonymous":
            code = row.get("http_status")
            if code is not None:
                return int(code)
    return None


def _authenticated_ok(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        mode = str(row.get("auth_mode") or "anonymous")
        if mode == "anonymous":
            continue
        if account_access_allowed(row.get("http_status")):
            return True
    return False


def classify_endpoint_rows(rows: list[dict[str, Any]]) -> EndpointAuthClass:
    """Derive auth requirement from Verify rows for one endpoint_id."""
    endpoint_id = str(rows[0].get("endpoint_id") or "") if rows else ""
    anon_status = _anonymous_status(rows)
    authed_ok = _authenticated_ok(rows)
    labels = tuple(infer_endpoint_auth_labels(rows))

    if anon_status in (401, 403) and authed_ok:
        requirement: AuthRequirement = "auth_required"
    elif anon_status is not None and account_access_allowed(anon_status):
        requirement = "optional_auth" if authed_ok else "public"
    elif authed_ok and anon_status in (404, 405, None):
        requirement = "unknown"
    elif authed_ok:
        requirement = "unknown"
    else:
        requirement = "unknown"

    return EndpointAuthClass(
        endpoint_id=endpoint_id,
        requirement=requirement,
        anonymous_status=anon_status,
        authenticated_ok=authed_ok,
        labels=labels,
    )


def load_verify_probe_results(data_dir: Path | None) -> list[dict[str, Any]]:
    if data_dir is None:
        return []
    path = data_dir / VERIFY_REPORT_NAME
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        results = raw.get("results")
        return [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def build_endpoint_auth_index(data_dir: Path | None) -> dict[str, EndpointAuthClass]:
    """endpoint_id → auth requirement (from verify-report.json)."""
    results = load_verify_probe_results(data_dir)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in results:
        eid = str(row.get("endpoint_id") or "")
        if eid:
            grouped.setdefault(eid, []).append(row)

    return {eid: classify_endpoint_rows(rows) for eid, rows in grouped.items()}


def classify_endpoint_by_id(
    data_dir: Path | None,
    endpoint_id: str,
) -> EndpointAuthClass | None:
    results = load_verify_probe_results(data_dir)
    rows = [r for r in results if str(r.get("endpoint_id") or "") == endpoint_id]
    if not rows:
        return None
    return classify_endpoint_rows(rows)


def account_access_summary(data_dir: Path | None, endpoint_id: str) -> list[dict[str, Any]]:
    """Per-endpoint anonymous vs authenticated rows (inventory API shape)."""
    return account_access_for_endpoint(load_verify_probe_results(data_dir), endpoint_id)


def filter_cookie_probe_endpoints(
    endpoints: list[Any],
    auth_index: dict[str, EndpointAuthClass],
    *,
    auth_required_only: bool = True,
) -> tuple[list[Any], dict[str, Any]]:
    """Keep endpoints where cookie cross/tamper probes are meaningful."""
    kept: list[Any] = []
    skipped: list[dict[str, str]] = []
    counts: dict[str, int] = {
        "auth_required": 0,
        "public": 0,
        "optional_auth": 0,
        "unknown": 0,
        "unindexed": 0,
    }

    for ep in endpoints:
        eid = str(getattr(ep, "endpoint_id", "") or "")
        auth_cls = auth_index.get(eid)
        if auth_cls is None:
            counts["unindexed"] += 1
            if not auth_required_only:
                kept.append(ep)
            else:
                skipped.append({"endpoint_id": eid, "reason": "unindexed"})
            continue

        counts[auth_cls.requirement] += 1
        if auth_cls.cookie_probe_relevant() or not auth_required_only:
            kept.append(ep)
        else:
            skipped.append(
                {
                    "endpoint_id": eid,
                    "reason": auth_cls.requirement,
                    "anonymous_status": str(auth_cls.anonymous_status),
                }
            )

    stats = {
        "input": len(endpoints),
        "kept": len(kept),
        "skipped": len(skipped),
        "counts": counts,
        "auth_required_only": auth_required_only,
    }
    if skipped:
        stats["skipped_sample"] = skipped[:12]
    return kept, stats


def auth_requirement_summary(auth_index: dict[str, EndpointAuthClass]) -> dict[str, int]:
    summary = {"auth_required": 0, "public": 0, "optional_auth": 0, "unknown": 0}
    for cls in auth_index.values():
        summary[cls.requirement] = summary.get(cls.requirement, 0) + 1
    return summary
