"""HTTP login enumeration probes for guideline 6-2."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.services.zap_util import probe_url
from diagnosis.result import DiagnosisFinding


DEFAULT_WRONG_PASSWORD = "__ARGUS_INVALID_PASSWORD__"


def _is_api_login_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return "/api/" in path or path.endswith("/auth/login") and "/api" in path


def _post_login_once(
    client: httpx.Client,
    *,
    url: str,
    mode: str,
    id_field: str,
    pw_field: str,
    email: str,
    password: str,
    timeout: float,
) -> tuple[int | None, str, str | None, str | None]:
    payload = {id_field: email, pw_field: password}
    headers = {"User-Agent": "ARGUS-6-2/1.0"}
    try:
        if mode == "json":
            resp = client.post(
                url,
                json=payload,
                timeout=timeout,
                headers={**headers, "Accept": "application/json, */*"},
            )
        else:
            resp = client.post(
                url,
                data=payload,
                timeout=timeout,
                headers={**headers, "Accept": "text/html, application/json, */*"},
                follow_redirects=True,
            )
        ctype = resp.headers.get("content-type")
        return resp.status_code, resp.text, ctype, None
    except httpx.HTTPError as exc:
        return None, "", None, str(exc)[:200]


def _post_login(
    client: httpx.Client,
    *,
    login_url: str,
    id_field: str,
    pw_field: str,
    email: str,
    password: str,
    timeout: float,
) -> tuple[int | None, str, str | None, str | None, str]:
    """POST login attempt; returns (status, body, ctype, error, probe_mode)."""
    url = probe_url(login_url)
    api_like = _is_api_login_url(url)

    if api_like:
        status, body, ctype, err = _post_login_once(
            client,
            url=url,
            mode="json",
            id_field=id_field,
            pw_field=pw_field,
            email=email,
            password=password,
            timeout=timeout,
        )
        return status, body, ctype, err, "json"

    # Login page URL — form POST first (typical HTML login)
    status, body, ctype, err = _post_login_once(
        client,
        url=url,
        mode="form",
        id_field=id_field,
        pw_field=pw_field,
        email=email,
        password=password,
        timeout=timeout,
    )
    if err is None and status not in (404, 405, 415, None):
        return status, body, ctype, err, "form"

    # Fallback: some apps accept JSON on the same path
    status2, body2, ctype2, err2 = _post_login_once(
        client,
        url=url,
        mode="json",
        id_field=id_field,
        pw_field=pw_field,
        email=email,
        password=password,
        timeout=timeout,
    )
    if err2 is None and (err is not None or (status2 not in (404, 405, 415, None))):
        return status2, body2, ctype2, err2, "json"

    return status, body, ctype, err, "form"


def run_login_enumeration_probes(
    login_entries: list[dict[str, str]],
    *,
    auth_cfg: dict[str, Any],
    account_email: str,
    account_password: str,
    snapshot_fn: Any,
    compare_set_fn: Any,
    fake_email: str,
    wrong_password: str = DEFAULT_WRONG_PASSWORD,
    timeout: float = 10.0,
    strict: bool = True,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    id_field = str(auth_cfg.get("id_field") or "email")
    pw_field = str(auth_cfg.get("pw_field") or "password")

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "login_entries": len(login_entries),
        "probed": 0,
        "uniform": 0,
        "enumeration_risk": 0,
        "errors": 0,
        "account_email": account_email,
        "fake_email": fake_email,
        "strict": strict,
    }

    with httpx.Client() as client:
        for entry in login_entries:
            login_url = entry["url"]
            label = entry.get("label") or login_url
            stats["probed"] += 1

            status_a, body_a, ctype_a, err_a, mode_a = _post_login(
                client,
                login_url=login_url,
                id_field=id_field,
                pw_field=pw_field,
                email=account_email,
                password=wrong_password,
                timeout=timeout,
            )
            status_b, body_b, ctype_b, err_b, mode_b = _post_login(
                client,
                login_url=login_url,
                id_field=id_field,
                pw_field=pw_field,
                email=fake_email,
                password=wrong_password,
                timeout=timeout,
            )
            status_c, body_c, ctype_c, err_c, mode_c = _post_login(
                client,
                login_url=login_url,
                id_field=id_field,
                pw_field=pw_field,
                email=fake_email,
                password=account_password,
                timeout=timeout,
            )
            probe_mode = "/".join(dict.fromkeys(m for m in (mode_a, mode_b, mode_c) if m))

            snap_a = snapshot_fn(
                scenario="exists_wrong_password",
                email=account_email,
                status=status_a,
                body=body_a,
                content_type=ctype_a,
                error=err_a,
            )
            snap_b = snapshot_fn(
                scenario="nonexistent_wrong_password",
                email=fake_email,
                status=status_b,
                body=body_b,
                content_type=ctype_b,
                error=err_b,
            )
            snap_c = snapshot_fn(
                scenario="nonexistent_valid_password",
                email=fake_email,
                status=status_c,
                body=body_c,
                content_type=ctype_c,
                error=err_c,
            )
            scenarios = [snap_a, snap_b, snap_c]

            if err_a or err_b or err_c:
                stats["errors"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=(
                            f"[6-2] Login probe unreachable at `{label}`"
                            f"{f': {err_a or err_b or err_c}' if (err_a or err_b or err_c) else ''}"
                        ),
                        evidence={
                            "rule_id": "6-2-login-enumeration",
                            "source": "httpx",
                            "engine": "httpx",
                            "login_url": probe_url(login_url),
                            "login_label": label,
                            "probe_mode": probe_mode,
                            "scenario_a": snap_a.to_dict(),
                            "scenario_b": snap_b.to_dict(),
                            "scenario_c": snap_c.to_dict(),
                            "error": err_a or err_b or err_c,
                        },
                    )
                )
                continue

            comparison = compare_set_fn(scenarios, strict=strict)

            base_evidence: dict[str, Any] = {
                "rule_id": "6-2-login-enumeration",
                "source": "httpx",
                "engine": "httpx",
                "login_url": probe_url(login_url),
                "login_label": label,
                "probe_mode": probe_mode,
                "scenario_a": snap_a.to_dict(),
                "scenario_b": snap_b.to_dict(),
                "scenario_c": snap_c.to_dict(),
                "comparison": comparison.to_dict(),
                "remediation": (
                    "Return the same generic login failure message and HTTP status for all "
                    "failed logins: existing user + wrong password, unknown user + wrong "
                    "password, and unknown user + valid password (e.g. invalid credentials)"
                ),
            }

            if comparison.uniform:
                stats["uniform"] += 1
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=(
                            f"[6-2] Uniform login failure at `{label}` — "
                            f"A/B/C responses match"
                        ),
                        evidence=base_evidence,
                    )
                )
            else:
                stats["enumeration_risk"] += 1
                diff_summary = "; ".join(comparison.differences)
                findings.append(
                    DiagnosisFinding(
                        severity="medium",
                        message=(
                            f"[6-2] Login failure exposes account enumeration at `{label}`: "
                            f"{diff_summary}"
                        ),
                        evidence={
                            **base_evidence,
                            "differences": comparison.differences,
                            "reason": (
                                "Distinct failure responses across login failure scenarios "
                                "(existing vs missing account, wrong vs valid password)"
                            ),
                        },
                    )
                )

    return findings, stats
