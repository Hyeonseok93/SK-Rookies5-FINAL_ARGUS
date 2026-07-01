"""httpx cookie cross-use and tamper probes (4-1 phase A)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from app.services.zap_util import probe_url
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint


def _probe(
    client: httpx.Client,
    ep: Endpoint,
    auth: dict[str, Any] | None,
    *,
    timeout: float,
) -> tuple[int | None, str, bytes, str | None]:
    try:
        probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
    except Exception as exc:
        return None, "", b"", str(exc)[:200]

    method = probe["method"]
    url = probe["url"]
    headers = dict(probe.get("headers") or {})
    body = probe.get("body") or ""
    try:
        resp = client.request(
            method,
            url,
            headers=headers,
            content=body if body else None,
            timeout=timeout,
            follow_redirects=True,
        )
        return resp.status_code, url, resp.content or b"", None
    except httpx.HTTPError as exc:
        return None, url, b"", str(exc)[:200]


def run_cross_cookie_probes(
    endpoints: list[Endpoint],
    sessions: list[dict[str, Any]],
    *,
    auth_profiles: list[str],
    cross_session_pairs_fn: Any,
    session_with_profile_fn: Any,
    access_allowed_fn: Any,
    cross_cookie_leak_detected_fn: Any,
    cross_cookie_leak_meta_fn: Any,
    body_fingerprint_fn: Any,
    is_admin_api_path_fn: Any,
    make_cross_finding_fn: Any,
    timeout: float = 8.0,
    max_pairs_per_endpoint: int = 12,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    findings: list[Any] = []
    stats: dict[str, Any] = {
        "endpoints": len(endpoints),
        "sessions": len(sessions),
        "auth_profiles": auth_profiles,
        "pairs": 0,
        "probed": 0,
        "cross_status_both_ok": 0,
        "cross_same_body": 0,
        "cross_body_mismatch": 0,
        "cross_generic_excluded": 0,
        "by_profile": {p: {"cross_same_body": 0} for p in auth_profiles},
        "errors": 0,
    }

    if len(sessions) < 2:
        stats["skipped"] = "need_at_least_two_sessions"
        return findings, stats

    pairs = cross_session_pairs_fn(sessions)

    with httpx.Client() as client:
        for ep_idx, ep in enumerate(endpoints, 1):
            if on_progress:
                on_progress(
                    endpoints_done=ep_idx,
                    endpoints_total=len(endpoints),
                    endpoint_id=(ep.path or ep.id or "")[:80],
                )
            for profile in auth_profiles:
                pair_count = 0
                for owner, other in pairs:
                    if pair_count >= max_pairs_per_endpoint:
                        break
                    owner_auth = session_with_profile_fn(owner, profile)
                    other_auth = session_with_profile_fn(other, profile)

                    owner_status, url, owner_body, owner_err = _probe(
                        client, ep, owner_auth, timeout=timeout
                    )
                    stats["probed"] += 1
                    if owner_err:
                        stats["errors"] += 1
                        continue
                    if not access_allowed_fn(owner_status):
                        continue

                    other_status, _, other_body, other_err = _probe(
                        client, ep, other_auth, timeout=timeout
                    )
                    stats["probed"] += 1
                    pair_count += 1
                    stats["pairs"] += 1
                    if other_err:
                        stats["errors"] += 1
                        continue
                    if not access_allowed_fn(other_status):
                        continue

                    stats["cross_status_both_ok"] += 1
                    if not cross_cookie_leak_detected_fn(
                        owner_body,
                        other_body,
                        owner,
                        other,
                        path=ep.path,
                    ):
                        leak_meta = cross_cookie_leak_meta_fn(
                            owner_body, other_body, owner, other, path=ep.path
                        )
                        reason = str(leak_meta.get("reason") or "")
                        if reason in ("excluded_path", "generic_response_no_owner_identity"):
                            stats["cross_generic_excluded"] += 1
                        else:
                            stats["cross_body_mismatch"] += 1
                        continue

                    leak_meta = cross_cookie_leak_meta_fn(
                        owner_body, other_body, owner, other, path=ep.path
                    )
                    stats["cross_same_body"] += 1
                    stats["by_profile"][profile]["cross_same_body"] += 1
                    admin = is_admin_api_path_fn(ep.path)
                    rule_id = "4-1-admin-api-cross-cookie" if admin else "4-1-cross-account-cookie"
                    severity = "high" if admin else "medium"
                    trigger = "admin_api_cross_cookie" if admin else "cross_account_cookie"
                    findings.append(
                        make_cross_finding_fn(
                            rule_id=rule_id,
                            severity=severity,
                            owner=owner,
                            other=other,
                            ep=ep,
                            url=url,
                            owner_status=owner_status,
                            other_status=other_status,
                            owner_body_fp=body_fingerprint_fn(owner_body),
                            other_body_fp=body_fingerprint_fn(other_body),
                            trigger=trigger,
                            auth_profile=profile,
                            leak_meta=leak_meta,
                        )
                    )

    return findings, stats


def run_tamper_probes(
    endpoints: list[Endpoint],
    sessions: list[dict[str, Any]],
    *,
    auth_profiles: list[str],
    tampered_variants_fn: Any,
    access_allowed_fn: Any,
    make_tamper_finding_fn: Any,
    build_isolated_confirm_ctx_fn: Any,
    tamper_label_allowed_fn: Any,
    timeout: float = 8.0,
    max_endpoints: int = 30,
    max_variants_per_session: int = 24,
    partial_cross_tamper: bool = True,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    findings: list[Any] = []
    stats: dict[str, Any] = {
        "endpoints": min(len(endpoints), max_endpoints),
        "sessions": len(sessions),
        "auth_profiles": auth_profiles,
        "probed": 0,
        "tamper_accepted": 0,
        "tamper_combo_ok_isolated_rejected": 0,
        "tamper_frontend_only_skipped": 0,
        "by_profile": {p: {"tamper_accepted": 0} for p in auth_profiles},
        "errors": 0,
    }

    if not sessions:
        stats["skipped"] = "no_sessions"
        return findings, stats

    with httpx.Client() as client:
        tamper_eps = endpoints[:max_endpoints]
        for ep_idx, ep in enumerate(tamper_eps, 1):
            if on_progress:
                on_progress(
                    endpoints_done=ep_idx,
                    endpoints_total=len(tamper_eps),
                    endpoint_id=(ep.path or ep.id or "")[:80],
                )
            for profile in auth_profiles:
                for session in sessions[:6]:
                    owner_auth = {**session, "_auth_profile": profile}
                    owner_status, url, _, owner_err = _probe(client, ep, owner_auth, timeout=timeout)
                    stats["probed"] += 1
                    if owner_err or not access_allowed_fn(owner_status):
                        continue

                    others = [s for s in sessions if s is not session][:3]
                    variants = tampered_variants_fn(
                        session,
                        profile,
                        other_sessions=others if partial_cross_tamper else None,
                        include_partial_cross=partial_cross_tamper
                        and profile in ("dual", "browser_full"),
                    )
                    for label, tampered in variants[:max_variants_per_session]:
                        if not tamper_label_allowed_fn(label):
                            stats["tamper_frontend_only_skipped"] += 1
                            continue
                        t_status, _, _, t_err = _probe(client, ep, tampered, timeout=timeout)
                        stats["probed"] += 1
                        if t_err:
                            stats["errors"] += 1
                            continue
                        if not access_allowed_fn(t_status):
                            continue

                        confirm_ctx = build_isolated_confirm_ctx_fn(tampered, label)
                        confirm_status: int | None = None
                        if confirm_ctx is not None:
                            confirm_status, _, _, c_err = _probe(
                                client, ep, confirm_ctx, timeout=timeout
                            )
                            stats["probed"] += 1
                            if c_err or not access_allowed_fn(confirm_status):
                                stats["tamper_combo_ok_isolated_rejected"] += 1
                                continue

                        stats["tamper_accepted"] += 1
                        stats["by_profile"][profile]["tamper_accepted"] += 1
                        findings.append(
                            make_tamper_finding_fn(
                                session=session,
                                ep=ep,
                                url=url,
                                tamper_label=label,
                                owner_status=owner_status,
                                tamper_status=t_status,
                                auth_profile=profile,
                                confirm_status=confirm_status,
                                isolated_profile=confirm_ctx.get("_auth_profile") if confirm_ctx else None,
                            )
                        )

    return findings, stats
