"""Repeated failed-login probes for guideline 3-2."""

from __future__ import annotations

import importlib.util
import time
from pathlib import Path
from typing import Any

import httpx

from app.services.zap_util import probe_url
from diagnosis.result import DiagnosisFinding

DEFAULT_WRONG_PASSWORD = "__ARGUS_INVALID_PASSWORD__"


def _load_g62_probes():
    path = Path(__file__).resolve().parents[1] / "6-2" / "probes.py"
    mod_name = "diag_g62_probes_for_g32"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_G62 = _load_g62_probes()


def _post_login_once_with_retry_after(
    client: httpx.Client,
    *,
    url: str,
    mode: str,
    id_field: str,
    pw_field: str,
    email: str,
    password: str,
    timeout: float,
) -> tuple[int | None, str, str | None, str | None, str | None]:
    """POST once and retain Retry-After, which the shared 6-2 helper discards."""
    payload = {id_field: email, pw_field: password}
    headers = {"User-Agent": "ARGUS-3-2/1.0"}
    try:
        if mode == "json":
            response = client.post(
                url,
                json=payload,
                timeout=timeout,
                headers={**headers, "Accept": "application/json, */*"},
            )
        else:
            response = client.post(
                url,
                data=payload,
                timeout=timeout,
                headers={**headers, "Accept": "text/html, application/json, */*"},
                follow_redirects=True,
            )
        return (
            response.status_code,
            response.text,
            response.headers.get("content-type"),
            None,
            response.headers.get("retry-after"),
        )
    except httpx.HTTPError as exc:
        return None, "", None, str(exc)[:200], None


def _post_login_with_retry_after(
    client: httpx.Client,
    *,
    login_url: str,
    id_field: str,
    pw_field: str,
    email: str,
    password: str,
    timeout: float,
) -> tuple[int | None, str, str | None, str | None, str, str | None]:
    """Mirror 6-2's form/JSON fallback while also returning Retry-After."""
    url = probe_url(login_url)
    if _G62._is_api_login_url(url):
        status, body, ctype, err, retry_after = _post_login_once_with_retry_after(
            client, url=url, mode="json", id_field=id_field, pw_field=pw_field,
            email=email, password=password, timeout=timeout,
        )
        return status, body, ctype, err, "json", retry_after

    first = _post_login_once_with_retry_after(
        client, url=url, mode="form", id_field=id_field, pw_field=pw_field,
        email=email, password=password, timeout=timeout,
    )
    status, body, ctype, err, retry_after = first
    if err is None and status not in (404, 405, 415, None):
        return status, body, ctype, err, "form", retry_after

    second = _post_login_once_with_retry_after(
        client, url=url, mode="json", id_field=id_field, pw_field=pw_field,
        email=email, password=password, timeout=timeout,
    )
    status2, body2, ctype2, err2, retry_after2 = second
    if err2 is None and (err is not None or status2 not in (404, 405, 415, None)):
        return status2, body2, ctype2, err2, "json", retry_after2
    return status, body, ctype, err, "form", retry_after


def run_lockout_probes(
    login_entries: list[dict[str, str]],
    *,
    auth_cfg: dict[str, Any],
    account_email: str,
    wrong_password: str = DEFAULT_WRONG_PASSWORD,
    max_attempts: int = 6,
    interval_sec: float = 0.05,
    snapshot_fn: Any,
    analyze_fn: Any,
    timeout: float = 10.0,
    strict: bool = True,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    id_field = str(auth_cfg.get("id_field") or "email")
    pw_field = str(auth_cfg.get("pw_field") or "password")

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "login_entries": len(login_entries),
        "probed": 0,
        "limit_detected": 0,
        "no_limit": 0,
        "errors": 0,
        "max_attempts": max_attempts,
        "account_email": account_email,
        "strict": strict,
    }

    with httpx.Client() as client:
        for entry in login_entries:
            login_url = entry["url"]
            label = entry.get("label") or login_url
            stats["probed"] += 1

            snapshots = []
            retry_after_headers: list[str | None] = []
            attempt_rows: list[dict[str, Any]] = []
            probe_mode = "json"
            last_err: str | None = None

            for attempt in range(1, max_attempts + 1):
                status, body, ctype, err, mode, retry_after = _post_login_with_retry_after(
                    client,
                    login_url=login_url,
                    id_field=id_field,
                    pw_field=pw_field,
                    email=account_email,
                    password=wrong_password,
                    timeout=timeout,
                )
                probe_mode = mode
                if err:
                    last_err = err
                    snap = snapshot_fn(
                        scenario=f"attempt_{attempt}",
                        email=account_email,
                        status=status,
                        body=body,
                        content_type=ctype,
                        error=err,
                    )
                else:
                    snap = snapshot_fn(
                        scenario=f"attempt_{attempt}",
                        email=account_email,
                        status=status,
                        body=body,
                        content_type=ctype,
                        error=None,
                    )
                snapshots.append(snap)
                retry_after_headers.append(retry_after)
                attempt_rows.append(
                    {
                        "attempt": attempt,
                        "http_status": status,
                        "error_code": snap.error_code,
                        "primary_message": snap.primary_message,
                        "body_fingerprint": snap.body_fingerprint,
                        "retry_after": retry_after,
                        "error": err,
                    }
                )
                if attempt < max_attempts and interval_sec > 0:
                    time.sleep(interval_sec)

            analysis = analyze_fn(
                snapshots,
                retry_after_headers=retry_after_headers,
                strict=strict,
            )

            base_evidence: dict[str, Any] = {
                "rule_id": "3-2-auth-failure-limit",
                "engine": "httpx",
                "login_url": probe_url(login_url),
                "login_label": label,
                "probe_mode": probe_mode,
                "account_email": account_email,
                "max_attempts": max_attempts,
                "attempts": attempt_rows,
                "analysis": analysis.to_dict(),
                "remediation": (
                    "Enforce account lockout or rate limiting after repeated failed logins "
                    "(e.g. lock account or return 429 after N failures)"
                ),
            }

            if last_err and all(s.error for s in snapshots):
                stats["errors"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"[3-2] Login lockout probe unreachable at `{label}`: {last_err}",
                        evidence={**base_evidence, "trigger": "probe_unreachable", "error": last_err},
                    )
                )
                continue

            if analysis.detected:
                stats["limit_detected"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=(
                            f"[3-2] Auth failure limit detected at `{label}` — "
                            f"attempt {analysis.detected_at_attempt}/{max_attempts} "
                            f"({analysis.limit_type}: {analysis.reason})"
                        ),
                        evidence={
                            **base_evidence,
                            "trigger": "lockout_detected",
                            "limit_type": analysis.limit_type,
                            "detected_at_attempt": analysis.detected_at_attempt,
                        },
                    )
                )
            else:
                stats["no_limit"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="medium",
                        message=(
                            f"[3-2] No auth failure limit at `{label}` — "
                            "5 consecutive failures produced no lockout/rate limit "
                            f"({max_attempts} total attempts, response unchanged)"
                        ),
                        evidence={
                            **base_evidence,
                            "trigger": "no_lockout_detected",
                            "reason": analysis.reason,
                        },
                    )
                )

    return findings, stats
