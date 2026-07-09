"""Playwright HTTP replay for selected 1-2 findings."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from credentials import ReplayCredential, credential_for_url
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


def ui_url_for_api(url: str) -> tuple[str, str]:
    """Map an API finding to the real ONDE page that uses that API."""
    path = urlsplit(str(url or "")).path.lower()
    if "/api/v1/posts" in path:
        route = "/feed"
    elif "/api/v1/auth/signup" in path:
        route = "/signup/email"
    elif "/api/v1/admin/" in path:
        route = "/admin"
    elif "/api/v1/flights" in path:
        route = "/flight"
    elif "/api/v1/cars" in path:
        route = "/car"
    elif "/api/v1/insurances" in path:
        route = "/insurance"
    else:
        route = "/"
    return (
        f"http://localhost:5173{route}",
        f"http://localhost:5173{route}",
    )


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


def _login_url(target_url: str, credential: ReplayCredential) -> str:
    parts = urlsplit(target_url)
    path = "/api/v1/auth/admin/login" if credential.role == "admin" else "/api/v1/auth/login"
    port = 8080 if parts.port in {None, 8080, 8081} else parts.port
    host = parts.hostname or "host.docker.internal"
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme or "http", netloc, path, "", ""))


def _login(request_context: Any, target_url: str, credential: ReplayCredential) -> dict[str, Any]:
    url = _login_url(target_url, credential)
    response = request_context.post(
        url,
        data={"email": credential.email, "password": credential.password},
        timeout=15_000,
    )
    return {"role": credential.role, "email": credential.email, "status": response.status, "ok": response.ok}


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


def replay_case(case: EvidenceCase) -> EvidenceCase:
    allowed, reason = replay_allowed(case.baseline.method, case.baseline.url)
    if not allowed:
        raise RuntimeError(reason)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is required for HTTP evidence replay.") from exc

    credential = credential_for_url(case.baseline.url)
    metadata = dict(case.metadata)
    with sync_playwright() as playwright:
        request_context = playwright.request.new_context(ignore_https_errors=True)
        login = _login(request_context, case.baseline.url, credential)
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
