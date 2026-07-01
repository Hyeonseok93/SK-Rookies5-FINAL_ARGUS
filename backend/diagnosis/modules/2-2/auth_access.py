"""Anonymous vs authenticated download probes (guideline 2-2 item 5)."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.zap_util import probe_url
from diagnosis.replay.recorder import ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint

_DIR = Path(__file__).resolve().parent


def _load_traversal_fuzz():
    spec = importlib.util.spec_from_file_location("diag_g22_traversal_fuzz_auth", _DIR / "traversal_fuzz.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load traversal_fuzz")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_tf = _load_traversal_fuzz()

MIN_FILE_BODY_BYTES = 128


@dataclass
class AuthProbeSnapshot:
    auth_mode: str
    http_status: int | None
    body: bytes
    headers: dict[str, str]
    url: str
    account_email: str | None = None
    error: str | None = None

    @property
    def fingerprint(self) -> dict[str, Any]:
        return _tf.body_fingerprint(self.body)


def _is_success(status: int | None) -> bool:
    return status is not None and 200 <= int(status) < 400


def is_download_like(
    *,
    http_status: int | None,
    body: bytes,
    headers: dict[str, str],
    path: str,
) -> tuple[bool, str]:
    """Heuristic: response looks like a file download (not generic JSON/HTML page)."""
    if not _is_success(http_status):
        return False, ""

    if _tf.is_pdf_or_binary(body, headers):
        return True, "pdf_or_binary"

    if _tf.has_attachment_disposition(headers):
        return True, "attachment"

    ctype = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    size = len(body)
    if size >= MIN_FILE_BODY_BYTES and any(k in path.lower() for k in _tf.EXPORT_LIKE_PATH):
        if "json" in ctype and size < 4096:
            return False, ""
        if "html" in ctype:
            return False, ""
        if "text/plain" not in ctype and "json" not in ctype:
            return True, "export_path_binary"
        if size >= 1024:
            return True, "export_path_large_body"

    return False, ""


def classify_unauth_download(
    *,
    path: str,
    anonymous: AuthProbeSnapshot,
    authenticated: AuthProbeSnapshot | None,
) -> tuple[str, str, dict[str, Any]] | None:
    """
    Return (severity, trigger, meta) when anonymous access to a download-like response is detected.
    None = no finding (expected auth gate or inconclusive).
    """
    anon_dl, anon_signal = is_download_like(
        http_status=anonymous.http_status,
        body=anonymous.body,
        headers=anonymous.headers,
        path=path,
    )
    if not anon_dl:
        return None

    meta: dict[str, Any] = {
        "anonymous_http_status": anonymous.http_status,
        "anonymous_signal": anon_signal,
        "anonymous_sha256": anonymous.fingerprint["sha256"],
        "anonymous_size": anonymous.fingerprint["size"],
        "anonymous_url": anonymous.url,
    }

    if authenticated is None:
        meta["auth_comparison"] = "no_test_account"
        return (
            "medium",
            "unauth_download_no_account",
            meta,
        )

    auth_dl, auth_signal = is_download_like(
        http_status=authenticated.http_status,
        body=authenticated.body,
        headers=authenticated.headers,
        path=path,
    )
    meta.update(
        {
            "authenticated_http_status": authenticated.http_status,
            "authenticated_signal": auth_signal,
            "authenticated_sha256": authenticated.fingerprint["sha256"],
            "authenticated_size": authenticated.fingerprint["size"],
            "authenticated_url": authenticated.url,
            "account_email": authenticated.account_email,
        }
    )

    auth_status = authenticated.http_status
    if auth_status in (401, 403) and not auth_dl:
        meta["auth_comparison"] = "anonymous_ok_auth_denied"
        return (
            "high",
            "anon_download_auth_denied",
            meta,
        )

    if _is_success(auth_status) and auth_dl:
        same_body = anonymous.fingerprint["sha256"] == authenticated.fingerprint["sha256"]
        meta["bodies_identical"] = same_body
        meta["auth_comparison"] = "both_download"
        severity = "medium"
        if any(k in path.lower() for k in ("admin", "internal", "private", "backup")):
            severity = "high"
        return (
            severity,
            "unauth_download_both_sessions",
            meta,
        )

    if not _is_success(auth_status) and auth_status not in (401, 403, None):
        meta["auth_comparison"] = "anonymous_ok_auth_error"
        return (
            "medium",
            "unauth_download_auth_failed",
            meta,
        )

    meta["auth_comparison"] = "anonymous_ok_auth_not_download"
    return (
        "medium",
        "unauth_download_auth_no_file",
        meta,
    )


TRIGGER_LABELS: dict[str, str] = {
    "anon_download_auth_denied": (
        "Anonymous request returns file/download; authenticated session gets 401/403"
    ),
    "unauth_download_both_sessions": (
        "File/download reachable without login (same or similar response when authenticated)"
    ),
    "unauth_download_auth_failed": (
        "Anonymous download; authenticated probe did not succeed (check parameters)"
    ),
    "unauth_download_auth_no_file": (
        "Anonymous download-like response; authenticated probe succeeded without file body"
    ),
    "unauth_download_no_account": (
        "Anonymous download-like response (no test account — configure auth for comparison)"
    ),
}


def _probe_endpoint(
    transport: Any,
    ep: Endpoint,
    *,
    auth: dict[str, Any] | None,
    auth_mode: str,
    account_email: str | None = None,
) -> AuthProbeSnapshot:
    probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
    method = probe["method"]
    url = probe["url"]
    headers = dict(probe.get("headers") or {})
    body_str = probe.get("body") or ""
    body_bytes = body_str.encode("utf-8") if body_str else None

    resp = transport.request(method, url, headers, body_bytes, follow_redirects=True)
    if resp.error:
        return AuthProbeSnapshot(
            auth_mode=auth_mode,
            http_status=None,
            body=b"",
            headers={},
            url=url,
            account_email=account_email,
            error=resp.error,
        )
    return AuthProbeSnapshot(
        auth_mode=auth_mode,
        http_status=resp.status,
        body=resp.body,
        headers=resp.headers,
        url=url,
        account_email=account_email,
    )


def _build_finding(
    ep: Endpoint,
    *,
    severity: str,
    trigger: str,
    meta: dict[str, Any],
    anonymous: AuthProbeSnapshot,
    authenticated: AuthProbeSnapshot | None,
    engine: str,
    auth: dict[str, Any] | None = None,
    replay_session: ReplaySession | None = None,
) -> DiagnosisFinding:
    snippet = _tf.evidence_snippet(anonymous.headers, anonymous.body)
    evidence: dict[str, Any] = {
        "source": engine,
        "engine": engine,
        "analysis_mode": "unified",
        "rule_id": "2-2-unauth-download",
        "classification": "B" if severity == "high" else "A",
        "trigger": trigger,
        "trigger_label": TRIGGER_LABELS.get(trigger, trigger),
        "related_sections": ["4-4"],
        "method": ep.method,
        "path": ep.path,
        "base_url": ep.base_url,
        "anonymous_http_status": anonymous.http_status,
        "http_status": anonymous.http_status,
        **snippet,
        **meta,
    }
    if authenticated:
        evidence["authenticated_http_status"] = authenticated.http_status
        if authenticated.account_email:
            evidence["account_email"] = authenticated.account_email

    if severity == "high":
        msg = (
            f"[B] Unauthenticated file/download on {ep.method} {ep.path} "
            f"(anonymous HTTP {anonymous.http_status}; auth HTTP {authenticated.http_status if authenticated else 'n/a'})"
        )
    else:
        msg = (
            f"[A] Download reachable without login on {ep.method} {ep.path} "
            f"(anonymous HTTP {anonymous.http_status})"
        )

    finding = DiagnosisFinding(severity=severity, message=msg, evidence=evidence)

    if replay_session and severity in ("medium", "high"):
        rec = replay_session.recorder(
            rule_id="2-2-unauth-download",
            path=ep.path,
            trigger=trigger,
        )
        rec.set_auth("anonymous")
        rec.append_ui_flow(method=ep.method, path=ep.path)
        anon_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=None)
        s_anon = rec.record_http_from_probe(
            "anon",
            label="Anonymous download probe",
            probe=anon_probe,
            response_status=anonymous.http_status,
            response_headers=anonymous.headers,
            response_body=anonymous.body,
            auth_mode="anonymous",
        )
        if authenticated and auth:
            rec.set_auth("authenticated", account_email=authenticated.account_email)
            rec.append_ui_flow(method=ep.method, path=ep.path)
            auth_probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
            s_auth = rec.record_http_from_probe(
                "auth",
                label=f"Authenticated probe ({authenticated.account_email})",
                probe=auth_probe,
                response_status=authenticated.http_status,
                response_headers=authenticated.headers,
                response_body=authenticated.body,
                auth_mode="authenticated",
                account_email=authenticated.account_email,
            )
            rec.record_compare(s_anon, s_auth, label="Anonymous vs authenticated download")
        return rec.attach_to(finding)

    return finding


def run_unauth_download_probes(
    candidates: list[Endpoint],
    *,
    transport: Any,
    engine: str,
    auth: dict[str, Any] | None = None,
    timeout: float = 12.0,
    replay_session: ReplaySession | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Probe each 2-2 candidate anonymously and with the primary logged-in account."""
    _ = timeout
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "engine": engine,
        "candidates": len(candidates),
        "probed": 0,
        "findings": 0,
        "skipped_no_anon": 0,
        "auth_configured": auth is not None,
    }

    if not candidates:
        return findings, stats

    for ep in candidates:
        anonymous = _probe_endpoint(transport, ep, auth=None, auth_mode="anonymous")
        authenticated: AuthProbeSnapshot | None = None
        if auth:
            authenticated = _probe_endpoint(
                transport,
                ep,
                auth=auth,
                auth_mode="authenticated",
                account_email=str(auth.get("email") or ""),
            )

        stats["probed"] += 1
        result = classify_unauth_download(
            path=ep.path,
            anonymous=anonymous,
            authenticated=authenticated,
        )
        if result is None:
            if anonymous.error:
                stats["errors"] = stats.get("errors", 0) + 1
            continue

        severity, trigger, meta = result
        if anonymous.error:
            meta["anonymous_error"] = anonymous.error
        if authenticated and authenticated.error:
            meta["authenticated_error"] = authenticated.error

        findings.append(
            _build_finding(
                ep,
                severity=severity,
                trigger=trigger,
                meta=meta,
                anonymous=anonymous,
                authenticated=authenticated,
                engine=engine,
                auth=auth,
                replay_session=replay_session,
            )
        )

    stats["findings"] = len(findings)
    return findings, stats
