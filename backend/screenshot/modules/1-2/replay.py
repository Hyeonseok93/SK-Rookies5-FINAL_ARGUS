"""Playwright HTTP replay for selected 1-2 findings."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from credentials import ReplayCredential
from models import EvidenceCase, HttpExchange
from redaction import redact_headers, redact_text

_BLOCKED_METHODS = {"DELETE", "PATCH"}
_BLOCKED_PATH_PARTS = {
    "cancel",
    "delete",
    "logout",
    "password-change",
    "password/reset",
    "payment",
    "refund",
    "withdraw",
}
_MAX_BODY_CHARS = 12_000


def display_url(url: str) -> str:
    return str(url or "").replace("host.docker.internal", "localhost")


def ui_url_for_api(frontend_base_url: str) -> tuple[str, str]:
    """Return a project-configured/discovered frontend root."""
    root = str(frontend_base_url or "").rstrip("/") + "/"
    return root, display_url(root)


def replay_allowed(method: str, url: str) -> tuple[bool, str]:
    normalized_method = str(method or "GET").upper()
    path = urlsplit(str(url or "")).path.lower()
    if normalized_method in _BLOCKED_METHODS:
        return False, f"{normalized_method} replay is blocked"
    if normalized_method == "PUT":
        return False, "PUT replay is blocked"
    if any(part in path for part in _BLOCKED_PATH_PARTS):
        return False, "destructive endpoint replay is blocked"
    return True, ""


def _mutate_query(url: str, parameter: str, payload: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    mutated: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == parameter:
            mutated.append((key, payload))
            replaced = True
        else:
            mutated.append((key, value))
    if not replaced:
        mutated.append((parameter, payload))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))


def _mutate_json_body(body: str, parameter: str, payload: str) -> str:
    try:
        parsed = json.loads(body or "{}")
    except json.JSONDecodeError:
        return body
    if not isinstance(parsed, dict):
        return body
    parsed[parameter] = payload
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


def attack_exchange(case: EvidenceCase, payload: str | None = None) -> HttpExchange:
    chosen_payload = str(payload if payload is not None else case.payload)
    baseline = case.baseline
    content_type = next(
        (value for key, value in baseline.request_headers.items() if key.lower() == "content-type"),
        "",
    ).lower()
    url = baseline.url
    body = baseline.request_body
    if "json" in content_type or (body.strip().startswith("{") and body.strip().endswith("}")):
        body = _mutate_json_body(body, case.parameter, chosen_payload)
    else:
        url = _mutate_query(url, case.parameter, chosen_payload)
    return replace(
        baseline,
        url=url,
        display_url=display_url(url),
        request_body=body,
        status_code=None,
        response_headers={},
        response_body="",
        elapsed_ms=None,
    )


def _login(
    request_context: Any,
    url: str,
    credential: ReplayCredential,
    id_field: str,
    password_field: str,
) -> dict[str, Any]:
    response = request_context.post(
        url,
        data={id_field: credential.identifier, password_field: credential.password},
        timeout=15_000,
    )
    return {
        "account_id": credential.account_id,
        "login_url": display_url(url),
        "runtime_login_url": url,
        "status": response.status,
        "ok": response.ok,
    }


def _perform(request_context: Any, exchange: HttpExchange) -> HttpExchange:
    headers = {
        key: value
        for key, value in exchange.request_headers.items()
        if key.lower() not in {"cookie", "content-length", "host", "authorization"}
    }
    kwargs: dict[str, Any] = {
        "method": exchange.method.upper(),
        "headers": headers,
        "timeout": 20_000,
        "fail_on_status_code": False,
    }
    if exchange.request_body:
        kwargs["data"] = exchange.request_body
    started = time.perf_counter()
    response = request_context.fetch(exchange.url, **kwargs)
    elapsed_ms = (time.perf_counter() - started) * 1000
    body = response.text()[:_MAX_BODY_CHARS]
    return replace(
        exchange,
        display_url=display_url(exchange.url),
        request_headers=redact_headers(headers),
        request_body=redact_text(exchange.request_body),
        status_code=response.status,
        response_headers=redact_headers(dict(response.headers)),
        response_body=redact_text(body),
        elapsed_ms=elapsed_ms,
    )


def replay_case(
    case: EvidenceCase,
    *,
    credentials: list[ReplayCredential],
    login_urls: list[str],
    id_field: str,
    password_field: str,
) -> EvidenceCase:
    allowed, reason = replay_allowed(case.baseline.method, case.baseline.url)
    if not allowed:
        raise RuntimeError(reason)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is required for HTTP evidence replay.") from exc

    metadata = dict(case.metadata)
    with sync_playwright() as playwright:
        request_context = playwright.request.new_context(ignore_https_errors=True)
        login: dict[str, Any] = {"ok": False, "reason": "No supplied account/login endpoint succeeded"}
        for login_url in login_urls:
            for credential in credentials:
                attempt = _login(
                    request_context,
                    login_url,
                    credential,
                    id_field,
                    password_field,
                )
                if attempt["ok"]:
                    login = attempt
                    break
            if login["ok"]:
                break
        baseline = _perform(request_context, case.baseline)

        methods = dict(metadata.get("verification_methods") or {})
        boolean = dict(methods.get("boolean_based") or {})
        if "BOOLEAN" in case.verification_type.upper() and boolean.get("false_payload"):
            chosen_payload = str(boolean["false_payload"])
        else:
            chosen_payload = case.payload
        attack = _perform(request_context, attack_exchange(case, chosen_payload))
        request_context.dispose()

    metadata["login"] = login
    metadata["replay"] = {
        "performed": True,
        "baseline_status": baseline.status_code,
        "attack_status": attack.status_code,
        "payload": chosen_payload,
    }
    return replace(case, baseline=baseline, attack=attack, payload=chosen_payload, metadata=metadata)
