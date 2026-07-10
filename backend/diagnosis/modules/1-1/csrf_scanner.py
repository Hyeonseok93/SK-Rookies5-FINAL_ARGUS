"""CSRF checks for ARGUS 1-1.

The scanner evaluates three independent defenses:
- Origin/Referer validation
- Anti-CSRF token validation
- SameSite cookie protection
"""

from __future__ import annotations

import requests


def _is_passed(status_code: int) -> bool:
    return status_code < 400 or status_code == 405


def scan_csrf_endpoint(
    *,
    method: str,
    api_url: str,
    body_json: dict,
    base_headers: dict,
    scan_account: dict,
    cookie_auth_header: str,
    check_csrf_token_absence,
    has_unsafe_samesite_cookie,
    extract_request_parts,
    format_http_request,
    format_http_response,
) -> list[dict]:
    """Return CSRF alerts for one state-changing endpoint."""
    csrf_token_present_in_request = any(
        "csrf" in str(header_name).lower() or "xsrf" in str(header_name).lower()
        for header_name in base_headers
    )

    headers_tampered_ref = {
        **base_headers,
        "Origin": "http://evil-attacker.local",
        "Referer": "http://evil-attacker.local/exploit.html",
    }
    headers_no_ref = {
        key: value
        for key, value in base_headers.items()
        if key.lower() not in {"origin", "referer"}
    }

    res_tampered_ref = requests.request(
        method=method.upper(),
        url=api_url,
        json=body_json,
        headers=headers_tampered_ref,
        timeout=4,
    )
    status_tampered_ref = res_tampered_ref.status_code

    res_no_ref = requests.request(
        method=method.upper(),
        url=api_url,
        json=body_json,
        headers=headers_no_ref,
        timeout=4,
    )
    status_no_ref = res_no_ref.status_code

    set_cookie = res_tampered_ref.headers.get("Set-Cookie", "").lower()
    has_cookie_session = bool(cookie_auth_header or set_cookie)
    has_unsafe_samesite = (
        has_unsafe_samesite_cookie(scan_account, set_cookie) if has_cookie_session else False
    )
    csrf_token_absent = (
        not csrf_token_present_in_request
        and check_csrf_token_absence(res_tampered_ref)
        and check_csrf_token_absence(res_no_ref)
    )
    origin_referrer_bypass = _is_passed(status_tampered_ref) or _is_passed(status_no_ref)

    failed_count = sum(
        [
            bool(origin_referrer_bypass),
            bool(csrf_token_absent),
            bool(has_unsafe_samesite),
        ]
    )
    is_high_risk = failed_count == 3
    is_medium_risk = failed_count == 2

    print(
        f"[CSRF DEBUG] {method.upper()} {api_url} -> "
        f"TamperedRef={status_tampered_ref}, NoRef={status_no_ref}, "
        f"OriginRefererBypass={origin_referrer_bypass}, "
        f"CsrfTokenAbsent={csrf_token_absent}, "
        f"UnsafeSameSite={has_unsafe_samesite}, FailedDefenses={failed_count}/3"
    )

    alerts: list[dict] = []
    if is_high_risk:
        csrf_req_parts = extract_request_parts(
            res_tampered_ref.request,
            body_json=body_json,
            query_params=None,
        )
        alerts.append(
            {
                "alert": "Cross-Site Request Forgery (CSRF) Vulnerability - Confirmed",
                "url": api_url,
                "method": method.upper(),
                "risk": "High",
                "confidence": "High",
                "param": "Referer/Token/SameSite",
                "attack": "Tampered Referer & Missing Token & Unsafe SameSite",
                "custom_type": "CSRF_CUSTOM",
                "evidence_request": format_http_request(res_tampered_ref.request),
                "evidence_response": format_http_response(res_tampered_ref),
                "parsed_request_headers": csrf_req_parts["parsed_request_headers"],
                "parsed_request_body": csrf_req_parts["parsed_request_body"],
                "parsed_request_query": csrf_req_parts["parsed_request_query"],
                "auth_token_used": csrf_req_parts["auth_token_used"],
                "login_required": csrf_req_parts["login_required"],
                "expected_status_code": status_tampered_ref,
                "screenshot_on": "response_received",
                "replay_script": csrf_req_parts["replay_script"],
                "description": (
                    "All three CSRF defenses failed: Origin/Referer validation, "
                    "anti-CSRF token validation, and SameSite cookie protection."
                ),
                "solution": (
                    "1. Validate Origin/Referer and block missing or tampered origins. "
                    "2. Add anti-CSRF token validation. "
                    "3. Set session cookies to SameSite=Lax or SameSite=Strict."
                ),
            }
        )
    elif is_medium_risk:
        csrf_req_parts = extract_request_parts(
            res_no_ref.request,
            body_json=body_json,
            query_params=None,
        )
        alerts.append(
            {
                "alert": "Cross-Site Request Forgery (CSRF) Vulnerability - Potential/Bypass",
                "url": api_url,
                "method": method.upper(),
                "risk": "Medium",
                "confidence": "Medium",
                "param": "Referer/Token",
                "attack": "Omitted Referer or Token",
                "custom_type": "CSRF_CUSTOM",
                "evidence_request": format_http_request(res_no_ref.request),
                "evidence_response": format_http_response(res_no_ref),
                "parsed_request_headers": csrf_req_parts["parsed_request_headers"],
                "parsed_request_body": csrf_req_parts["parsed_request_body"],
                "parsed_request_query": csrf_req_parts["parsed_request_query"],
                "auth_token_used": csrf_req_parts["auth_token_used"],
                "login_required": csrf_req_parts["login_required"],
                "expected_status_code": status_no_ref,
                "screenshot_on": "response_received",
                "replay_script": csrf_req_parts["replay_script"],
                "description": (
                    "Two of the three CSRF defenses failed. Review Origin/Referer "
                    "validation, anti-CSRF token validation, and SameSite cookie protection."
                ),
                "solution": (
                    "1. Block missing or tampered Origin/Referer requests. "
                    "2. Add anti-CSRF token validation. "
                    "3. Set session cookies to SameSite=Lax or SameSite=Strict."
                ),
            }
        )

    return alerts
