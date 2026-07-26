"""Authentication helpers for ARGUS 1-1."""

from __future__ import annotations

import base64
import hashlib
import json


def find_token_recursively_with_path(data, path: str = ""):
    if isinstance(data, dict):
        candidates = ["accessToken", "access_token", "token", "jwt", "authorization"]
        for candidate in candidates:
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if key.lower() == candidate.lower() and value is not None:
                    return str(value), current_path
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if "token" in key.lower() and isinstance(value, (str, int)):
                return str(value), current_path
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                result = find_token_recursively_with_path(value, current_path)
                if result:
                    return result
    elif isinstance(data, list):
        for index, item in enumerate(data):
            result = find_token_recursively_with_path(item, f"{path}[{index}]" if path else f"[{index}]")
            if result:
                return result
    return None


def decode_jwt_claims(token: str | None) -> tuple[str, dict]:
    clean_token = str(token or "").strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token.split(None, 1)[1]
    parts = clean_token.split(".")
    if len(parts) < 2:
        return clean_token, {}
    payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("utf-8")).decode("utf-8"))
    except Exception:
        payload = {}
    return clean_token, payload


def jwt_debug_summary(token: str | None) -> str:
    clean_token, payload = decode_jwt_claims(token)
    safe_claims = {key: payload.get(key) for key in ["sub", "auth", "role", "roles", "scope", "iss", "aud", "iat", "exp"] if key in payload}
    fingerprint = hashlib.sha256(str(clean_token).encode("utf-8")).hexdigest()[:12] if clean_token else "none"
    return f"fingerprint={fingerprint}, claims={safe_claims}"


def build_cookie_header_from_account(account: dict | None) -> str:
    cookies = (account or {}).get("cookies") or {}
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def build_auth_headers(token: str | None = None, account: dict | None = None, mode: str | None = None) -> dict:
    headers = {}
    account = account or {}
    if mode != "cookie" and token:
        clean_token, _ = decode_jwt_claims(token)
        headers["Authorization"] = f"Bearer {clean_token}"
    if mode != "bearer":
        cookie_header = build_cookie_header_from_account(account)
        if cookie_header:
            headers["Cookie"] = cookie_header
    return headers


def has_unsafe_samesite_cookie(account: dict | None, response_set_cookie: str = "") -> bool:
    attrs = (account or {}).get("cookie_attrs") or {}
    for meta in attrs.values():
        same_site = str(meta.get("samesite", "")).lower()
        if same_site not in {"lax", "strict"}:
            return True
    if response_set_cookie and "samesite" not in response_set_cookie.lower():
        return True
    return False


def is_admin_account(account: dict) -> bool:
    role_text = str(account.get("role", "")).lower()
    base_url_text = str(account.get("base_url", "")).lower()
    claims_text = str(account.get("claims", {}) or {}).lower()
    return bool(account.get("token") or account.get("cookies")) and (
        "admin" in role_text or "admin" in base_url_text or "admin" in claims_text
    )
