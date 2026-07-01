"""Detect account lockout / rate limiting from repeated failed login attempts (3-2)."""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOCKOUT_STATUS = frozenset({403, 423, 429})
_KEYWORD_RE = re.compile(
    r"(lock(?:ed|out)?|too many|rate.?limit|blocked|temporarily|"
    r"exceeded|attempts?|잠금|잠김|초과|제한|횟수|차단|일시)",
    re.IGNORECASE,
)


def _load_g62_login_rules():
    path = Path(__file__).resolve().parents[1] / "6-2" / "login_rules.py"
    mod_name = "diag_g62_login_rules_for_g32"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_LR = _load_g62_login_rules()
LoginResponseSnapshot = _LR.LoginResponseSnapshot
snapshot_from_http = _LR.snapshot_from_http
compare_login_snapshots = _LR.compare_login_snapshots


@dataclass
class LockoutAnalysis:
    detected: bool
    limit_type: str = "none"
    detected_at_attempt: int | None = None
    reason: str = ""
    differences: list[str] = field(default_factory=list)
    baseline: dict[str, Any] | None = None
    trigger_snapshot: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "limit_type": self.limit_type,
            "detected_at_attempt": self.detected_at_attempt,
            "reason": self.reason,
            "differences": self.differences,
            "baseline": self.baseline,
            "trigger_snapshot": self.trigger_snapshot,
        }


def _has_lockout_keywords(text: str | None) -> bool:
    if not text:
        return False
    return _KEYWORD_RE.search(text) is not None


def _classify_limit_type(
    *,
    status: int | None,
    message: str | None,
    retry_after: str | None,
) -> str:
    if status == 429 or retry_after:
        return "rate_limit"
    if status in (403, 423):
        return "account_lockout"
    if _has_lockout_keywords(message):
        return "response_message"
    return "response_change"


def analyze_lockout_sequence(
    snapshots: list[LoginResponseSnapshot],
    *,
    retry_after_headers: list[str | None],
    strict: bool = True,
) -> LockoutAnalysis:
    """Compare repeated failure responses against the first attempt(s)."""
    if not snapshots:
        return LockoutAnalysis(detected=False, reason="no attempts")

    if snapshots[0].error:
        return LockoutAnalysis(
            detected=False,
            reason=f"baseline unreachable: {snapshots[0].error}",
            baseline=snapshots[0].to_dict(),
        )

    baseline = snapshots[0]
    stable_fps = {baseline.body_fingerprint or ""}
    if len(snapshots) > 1 and not snapshots[1].error:
        stable_fps.add(snapshots[1].body_fingerprint or "")

    for idx, snap in enumerate(snapshots[1:], start=2):
        if snap.error:
            continue

        retry_after = retry_after_headers[idx - 1] if idx - 1 < len(retry_after_headers) else None

        if snap.http_status in _LOCKOUT_STATUS and baseline.http_status not in _LOCKOUT_STATUS:
            limit_type = _classify_limit_type(
                status=snap.http_status,
                message=snap.primary_message,
                retry_after=retry_after,
            )
            return LockoutAnalysis(
                detected=True,
                limit_type=limit_type,
                detected_at_attempt=idx,
                reason=f"HTTP {snap.http_status} after {idx - 1} baseline failure(s)",
                baseline=baseline.to_dict(),
                trigger_snapshot=snap.to_dict(),
            )

        if retry_after and idx > 2:
            return LockoutAnalysis(
                detected=True,
                limit_type="rate_limit",
                detected_at_attempt=idx,
                reason=f"Retry-After header present at attempt {idx}",
                baseline=baseline.to_dict(),
                trigger_snapshot=snap.to_dict(),
            )

        comparison = compare_login_snapshots(baseline, snap, strict=strict)
        if comparison.uniform:
            continue

        msg_hit = _has_lockout_keywords(snap.primary_message) or _has_lockout_keywords(
            snap.error_code
        )
        code_changed = (baseline.error_code or "").lower() != (snap.error_code or "").lower()
        status_changed = baseline.http_status != snap.http_status
        fp_changed = (snap.body_fingerprint or "") not in stable_fps

        if msg_hit or (status_changed and fp_changed) or (code_changed and fp_changed):
            limit_type = _classify_limit_type(
                status=snap.http_status,
                message=snap.primary_message,
                retry_after=retry_after,
            )
            return LockoutAnalysis(
                detected=True,
                limit_type=limit_type,
                detected_at_attempt=idx,
                reason="; ".join(comparison.differences) or "response changed after repeated failures",
                differences=comparison.differences,
                baseline=baseline.to_dict(),
                trigger_snapshot=snap.to_dict(),
            )

        if fp_changed and idx >= 3:
            return LockoutAnalysis(
                detected=True,
                limit_type="response_change",
                detected_at_attempt=idx,
                reason="; ".join(comparison.differences) or "failure response changed",
                differences=comparison.differences,
                baseline=baseline.to_dict(),
                trigger_snapshot=snap.to_dict(),
            )

    return LockoutAnalysis(
        detected=False,
        reason=f"no lockout signal within {len(snapshots)} attempt(s)",
        baseline=baseline.to_dict(),
    )
