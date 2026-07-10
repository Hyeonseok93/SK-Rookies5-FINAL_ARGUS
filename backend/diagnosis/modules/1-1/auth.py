"""Authentication helpers for ARGUS 1-1."""

from __future__ import annotations

from http.cookies import SimpleCookie
import base64
import hashlib
import json

import requests


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


def get_set_cookie_headers(response) -> list[str]:
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers and hasattr(raw_headers, "get_all"):
        values = raw_headers.get_all("Set-Cookie")
        if values:
            return list(values)
    header_value = response.headers.get("Set-Cookie", "")
    return [header_value] if header_value else []


def parse_set_cookie_headers(set_cookie_headers) -> tuple[dict, dict]:
    cookies = {}
    cookie_attrs = {}
    for header in set_cookie_headers or []:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            continue
        for name, morsel in parsed.items():
            cookies[name] = morsel.value
            cookie_attrs[name] = {
                "httponly": bool(morsel["httponly"]),
                "secure": bool(morsel["secure"]),
                "samesite": morsel["samesite"] or "",
                "path": morsel["path"] or "",
                "domain": morsel["domain"] or "",
            }
    return cookies, cookie_attrs


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


def extract_token_with_source_from_response(response, token_field: str = "") -> tuple[str, dict]:
    if token_field and token_field.strip():
        field = token_field.strip()
        if field.startswith("cookie.") or field.startswith("cookies."):
            cookie_name = field.split(".", 1)[1]
            token = response.cookies.get(cookie_name)
            if not token:
                raise ValueError(f"Response cookie '{cookie_name}' was not found.")
            return str(token), {"source": "cookie", "field": cookie_name}
        data = response.json()
        token = data
        for key in field.split("."):
            token = token.get(key)
            if not token:
                raise ValueError(f"Response JSON field '{field}' was not found.")
        return str(token), {"source": "json", "field": field}

    for header_name in ["Authorization", "X-Auth-Token", "token", "access-token"]:
        header_val = response.headers.get(header_name, response.headers.get(header_name.lower(), ""))
        if header_val:
            return (header_val.split(None, 1)[1] if "bearer " in header_val.lower() else header_val), {"source": "header", "field": header_name}
    try:
        detected = find_token_recursively_with_path(response.json())
        if detected:
            token, path = detected
            return (token.split(None, 1)[1] if token.lower().startswith("bearer ") else token), {"source": "json", "field": path}
    except Exception:
        pass
    for cookie_name in ["accessToken", "access_token", "jwt", "token", "session", "sid", "jsessionid"]:
        token_val = response.cookies.get(cookie_name)
        if token_val:
            return str(token_val), {"source": "cookie", "field": cookie_name}
    raise ValueError("Login succeeded, but no token was found.")


def extract_auth_context(login_url: str, id_field: str, pw_field: str, token_field: str, user_id: str, user_pw: str) -> dict:
    id_candidates = [id_field.strip()] if id_field and id_field.strip() else ["email", "username", "userid", "user_id", "loginId", "login_id", "id"]
    pw_candidates = [pw_field.strip()] if pw_field and pw_field.strip() else ["password", "passwd", "pw", "pass"]
    response = None
    last_error = None
    for candidate_id in id_candidates:
        for candidate_pw in pw_candidates:
            try:
                res = requests.post(login_url, json={candidate_id: user_id, candidate_pw: user_pw}, timeout=8)
                if res.ok:
                    response = res
                    break
                last_error = f"HTTP {res.status_code} - Body: {res.text[:200]}"
            except Exception as exc:
                last_error = str(exc)
        if response:
            break
    if not response:
        raise RuntimeError(f"All login attempts failed. Last error: {last_error}")
    token, token_meta = extract_token_with_source_from_response(response, token_field)
    set_cookie_headers = get_set_cookie_headers(response)
    cookies, cookie_attrs = parse_set_cookie_headers(set_cookie_headers)
    if not cookies:
        cookies = {cookie.name: cookie.value for cookie in response.cookies}
        cookie_attrs = {cookie.name: {} for cookie in response.cookies}
    clean_token, claims = decode_jwt_claims(token)
    return {
        "token": clean_token,
        "claims": claims,
        "token_source": token_meta.get("source", ""),
        "token_field": token_meta.get("field", ""),
        "cookies": cookies,
        "cookie_attrs": cookie_attrs,
        "set_cookie_headers": set_cookie_headers,
        "login_status_code": response.status_code,
    }


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
