"""Session lifecycle probes — re-login uniqueness and logout invalidation (4-2)."""

from __future__ import annotations

from typing import Any

import httpx

from app.services.auth_probe_service import login_account_at
from app.services.zap_util import probe_url
from diagnosis.result import DiagnosisFinding
from inventory.auth_util import auth_headers
from inventory.schema import build_full_url


def _snapshot_session(session: dict[str, Any]) -> dict[str, Any]:
    """Preserve issued tokens — simulates user logout without server revocation."""
    return dict(session)


def _probe_refresh_token(
    client: httpx.Client,
    *,
    base_url: str,
    refresh_path: str | None,
    session: dict[str, Any],
) -> tuple[int, str]:
    if not refresh_path:
        return 0, "no_refresh_path"
    refresh = str(session.get("refresh_token") or "").strip()
    if not refresh:
        return 0, "no_refresh_token"

    url = probe_url(build_full_url(base_url.rstrip("/"), refresh_path))
    bearer = refresh if refresh.startswith("Bearer ") else f"Bearer {refresh}"
    attempts: list[tuple[str, dict[str, Any]]] = [
        ("body", {"json": {"refreshToken": refresh}}),
        ("bearer", {"headers": {"Authorization": bearer}, "json": {}}),
        ("cookie", {"headers": {"Cookie": f"refreshToken={refresh}"}}),
    ]
    for mode, kwargs in attempts:
        try:
            resp = client.post(url, **kwargs)
            status = int(resp.status_code)
            if status in (200, 201):
                return status, mode
        except httpx.HTTPError:
            continue
    return 0, "failed"


def _token_fingerprint(session: dict[str, Any]) -> dict[str, str]:
    return {
        "access": str(session.get("access_token") or session.get("token") or ""),
        "refresh": str(session.get("refresh_token") or ""),
    }


def client_ip_headers(ip: str) -> dict[str, str]:
    """Simulate a client IP for apps behind reverse proxies."""
    value = str(ip or "").strip()
    if not value:
        return {}
    return {
        "X-Forwarded-For": value,
        "X-Real-IP": value,
        "Forwarded": f"for={value}",
    }


def probe_auth_check(
    client: httpx.Client,
    *,
    base_url: str,
    probe_path: str,
    session: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
) -> int:
    url = probe_url(build_full_url(base_url.rstrip("/"), probe_path))
    headers = auth_headers(session)
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = client.get(url, headers=headers)
        return int(resp.status_code)
    except httpx.HTTPError:
        return 0


def probe_relogin_token_uniqueness(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    *,
    timeout: float,
) -> tuple[DiagnosisFinding | None, dict[str, Any]]:
    """Login twice — access/refresh tokens must change between issuances."""
    stats: dict[str, Any] = {"login_url": login_url, "email": account.get("email")}
    try:
        first = login_account_at(auth_cfg, account, login_url, timeout=timeout)
        second = login_account_at(auth_cfg, account, login_url, timeout=timeout)
    except Exception as exc:
        stats["error"] = str(exc)
        return None, stats

    fp1 = _token_fingerprint(first)
    fp2 = _token_fingerprint(second)
    stats["first"] = {k: bool(v) for k, v in fp1.items()}
    stats["second"] = {k: bool(v) for k, v in fp2.items()}

    reused: list[str] = []
    if fp1["access"] and fp1["access"] == fp2["access"]:
        reused.append("access_token")
    if fp1["refresh"] and fp1["refresh"] == fp2["refresh"]:
        reused.append("refresh_token")

    if not reused:
        return None, stats

    return (
        DiagnosisFinding(
            severity="high",
            message=(
                f"[4-2] Same token reissued on re-login for `{account.get('email')}` "
                f"({', '.join(reused)})"
            ),
            evidence={
                "rule_id": "4-2-token-reuse",
                "reason": f"identical {' and '.join(reused)} on consecutive logins",
                "login_url": login_url,
                "email": account.get("email"),
                "reused_fields": reused,
                "remediation": "Issue a new session/token on every successful login",
            },
        ),
        stats,
    )


def probe_duplicate_login(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    *,
    base_url: str,
    probe_path: str,
    timeout: float,
) -> tuple[DiagnosisFinding | None, dict[str, Any]]:
    """
  First login → second login with same account.
  If the first session still authorizes, concurrent sessions are allowed (finding).
    """
    stats: dict[str, Any] = {"login_url": login_url, "email": account.get("email")}
    try:
        first = login_account_at(auth_cfg, account, login_url, timeout=timeout)
        second = login_account_at(auth_cfg, account, login_url, timeout=timeout)
    except Exception as exc:
        stats["error"] = str(exc)
        return None, stats

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        status_first_after = probe_auth_check(
            client, base_url=base_url, probe_path=probe_path, session=first
        )
        status_second = probe_auth_check(
            client, base_url=base_url, probe_path=probe_path, session=second
        )

    stats["first_session_status_after_second_login"] = status_first_after
    stats["second_session_status"] = status_second

    if status_first_after in (401, 403, 0):
        return None, stats

    if status_first_after == 200 and status_second == 200:
        return (
            DiagnosisFinding(
                severity="medium",
                message=(
                    f"[4-2] Concurrent sessions allowed for `{account.get('email')}` "
                    f"(first token still valid after second login)"
                ),
                evidence={
                    "rule_id": "4-2-duplicate-login",
                    "reason": "first login token still returns 200 after second login",
                    "login_url": login_url,
                    "email": account.get("email"),
                    "probe_path": probe_path,
                    "probe_status_first": status_first_after,
                    "probe_status_second": status_second,
                    "remediation": (
                        "Invalidate prior server-side session on new login or bind "
                        "session to a unique server key"
                    ),
                },
            ),
            stats,
        )

    return None, stats


def probe_duplicate_login_cross_ip(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    *,
    base_url: str,
    probe_path: str,
    timeout: float,
    client_ips: list[str],
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    Login from two simulated client IPs, then verify whether both sessions stay valid.
    """
    ips = [str(ip).strip() for ip in client_ips if str(ip).strip()]
    if len(ips) < 2:
        ips = ["203.0.113.10", "198.51.100.20"]
    ip_a, ip_b = ips[0], ips[1]
    email = str(account.get("email") or "")

    stats: dict[str, Any] = {
        "login_url": login_url,
        "email": email,
        "client_ip_a": ip_a,
        "client_ip_b": ip_b,
    }
    findings: list[DiagnosisFinding] = []

    try:
        first = login_account_at(
            auth_cfg,
            account,
            login_url,
            timeout=timeout,
            extra_headers=client_ip_headers(ip_a),
        )
        second = login_account_at(
            auth_cfg,
            account,
            login_url,
            timeout=timeout,
            extra_headers=client_ip_headers(ip_b),
        )
    except Exception as exc:
        stats["error"] = str(exc)
        return findings, stats

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        status_first_home = probe_auth_check(
            client,
            base_url=base_url,
            probe_path=probe_path,
            session=first,
            extra_headers=client_ip_headers(ip_a),
        )
        status_first_foreign = probe_auth_check(
            client,
            base_url=base_url,
            probe_path=probe_path,
            session=first,
            extra_headers=client_ip_headers(ip_b),
        )
        status_second = probe_auth_check(
            client,
            base_url=base_url,
            probe_path=probe_path,
            session=second,
            extra_headers=client_ip_headers(ip_b),
        )

    stats["first_session_status_same_ip"] = status_first_home
    stats["first_session_status_foreign_ip"] = status_first_foreign
    stats["second_session_status"] = status_second

    if status_first_home in (401, 403, 0):
        stats["skipped"] = "first_session_not_authorized"
        return findings, stats

    base_evidence = {
        "login_url": login_url,
        "email": email,
        "probe_path": probe_path,
        "client_ip_a": ip_a,
        "client_ip_b": ip_b,
        "probe_status_first_same_ip": status_first_home,
        "probe_status_first_foreign_ip": status_first_foreign,
        "probe_status_second": status_second,
    }

    if status_first_home in (200, 201, 204) and status_second in (200, 201, 204):
        findings.append(
            DiagnosisFinding(
                severity="medium",
                message=(
                    f"[4-2] Concurrent sessions from different IPs for `{email}` "
                    f"({ip_a} then {ip_b})"
                ),
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-duplicate-login-cross-ip",
                    "reason": (
                        "first login token still valid on original IP after second login "
                        "from a different simulated client IP"
                    ),
                    "remediation": (
                        "Invalidate prior sessions on new login or bind sessions to client IP "
                        "when policy requires single-location access"
                    ),
                },
            )
        )

    if (
        status_first_foreign in (200, 201, 204)
        and status_first_home in (200, 201, 204)
        and ip_a != ip_b
    ):
        findings.append(
            DiagnosisFinding(
                severity="low",
                message=(
                    f"[4-2] Session token not bound to login IP for `{email}` "
                    f"(valid under {ip_b} after login from {ip_a})"
                ),
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-no-ip-session-binding",
                    "reason": (
                        f"first session returns {status_first_foreign} when probed with foreign "
                        f"IP header {ip_b}"
                    ),
                    "remediation": (
                        "Bind access tokens to issuing client IP or use server-side session "
                        "records that track source IP"
                    ),
                },
            )
        )

    return findings, stats


def probe_logout_invalidation(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    logout_url: str,
    *,
    base_url: str,
    probe_path: str,
    timeout: float,
) -> tuple[DiagnosisFinding | None, dict[str, Any]]:
    """Login → authorized → logout → token must no longer authorize."""
    stats: dict[str, Any] = {
        "login_url": login_url,
        "logout_url": logout_url,
        "email": account.get("email"),
    }
    try:
        session = login_account_at(auth_cfg, account, login_url, timeout=timeout)
    except Exception as exc:
        stats["error"] = str(exc)
        return None, stats

    logout_probe = probe_url(logout_url)
    headers = auth_headers(session)

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        before = probe_auth_check(client, base_url=base_url, probe_path=probe_path, session=session)
        stats["status_before_logout"] = before
        try:
            resp = client.post(logout_probe, headers=headers)
            stats["logout_http_status"] = resp.status_code
        except httpx.HTTPError as exc:
            stats["logout_error"] = str(exc)
            return None, stats
        after = probe_auth_check(client, base_url=base_url, probe_path=probe_path, session=session)
        stats["status_after_logout"] = after

    if before not in (200, 201, 204):
        stats["skipped"] = "session_not_authorized_before_logout"
        return None, stats

    if after in (401, 403, 0):
        return None, stats

    return (
        DiagnosisFinding(
            severity="high",
            message=(
                f"[4-2] Token still valid after logout for `{account.get('email')}` "
                f"at `{logout_url}`"
            ),
            evidence={
                "rule_id": "4-2-logout-not-invalidating",
                "reason": f"auth probe returned {after} after logout (expected 401/403)",
                "login_url": login_url,
                "logout_url": logout_url,
                "email": account.get("email"),
                "probe_path": probe_path,
                "status_before_logout": before,
                "status_after_logout": after,
                "remediation": "Revoke server-side session and clear tokens on logout",
            },
        ),
        stats,
    )


def probe_client_only_logout(
    auth_cfg: dict[str, Any],
    account: dict[str, str],
    login_url: str,
    *,
    base_url: str,
    probe_path: str,
    refresh_path: str | None,
    timeout: float,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    Simulate SPA logout (clear client state only, no server API).
    Reuse captured access/refresh tokens — they must be rejected if logout is secure.
    """
    stats: dict[str, Any] = {
        "login_url": login_url,
        "email": account.get("email"),
        "mode": "client_only",
    }
    findings: list[DiagnosisFinding] = []
    email = str(account.get("email") or "")

    try:
        session = login_account_at(auth_cfg, account, login_url, timeout=timeout)
    except Exception as exc:
        stats["error"] = str(exc)
        return findings, stats

    frozen = _snapshot_session(session)
    stats["has_access_token"] = bool(frozen.get("access_token") or frozen.get("token"))
    stats["has_refresh_token"] = bool(frozen.get("refresh_token"))

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        before = probe_auth_check(client, base_url=base_url, probe_path=probe_path, session=frozen)
        stats["status_before_client_logout"] = before
        after_access = probe_auth_check(
            client, base_url=base_url, probe_path=probe_path, session=frozen
        )
        stats["status_after_client_logout"] = after_access
        refresh_status, refresh_mode = _probe_refresh_token(
            client,
            base_url=base_url,
            refresh_path=refresh_path,
            session=frozen,
        )
        stats["refresh_status_after_client_logout"] = refresh_status
        stats["refresh_probe_mode"] = refresh_mode

    if before not in (200, 201, 204):
        stats["skipped"] = "session_not_authorized_before_client_logout"
        return findings, stats

    base_evidence = {
        "login_url": login_url,
        "email": email,
        "probe_path": probe_path,
        "refresh_path": refresh_path,
        "status_before_client_logout": before,
        "logout_mode": "client_only_no_server_call",
    }

    if after_access in (200, 201, 204):
        findings.append(
            DiagnosisFinding(
                severity="medium",
                message=(
                    f"[4-2] Access token still valid after client-only logout for `{email}` "
                    f"(no server revoke — JWT valid until exp)"
                ),
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-token-valid-after-client-logout",
                    "reason": f"auth probe returned {after_access} without server logout API",
                    "status_after_client_logout": after_access,
                    "remediation": (
                        "Add server-side logout/revocation or accept JWT expiry-only policy "
                        "with short access-token TTL"
                    ),
                },
            )
        )

    if refresh_status in (200, 201):
        findings.append(
            DiagnosisFinding(
                severity="high",
                message=(
                    f"[4-2] Refresh token still issues access after client-only logout "
                    f"for `{email}`"
                ),
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-refresh-valid-after-client-logout",
                    "reason": (
                        f"refresh endpoint returned {refresh_status} via {refresh_mode} "
                        "after simulated client logout"
                    ),
                    "refresh_status": refresh_status,
                    "refresh_probe_mode": refresh_mode,
                    "remediation": (
                        "Revoke refresh tokens server-side on logout and delete Redis/session "
                        "entries"
                    ),
                },
            )
        )

    return findings, stats
