from http.cookies import SimpleCookie
import base64
import hashlib
import json

import requests


def find_token_recursively(data):
    if isinstance(data, dict):
        candidates = ["accessToken", "access_token", "token", "jwt", "authorization"]
        for candidate in candidates:
            for key, value in data.items():
                if key.lower() == candidate.lower() and value is not None:
                    return str(value)

        for key, value in data.items():
            if "token" in key.lower() and isinstance(value, (str, int)):
                return str(value)

        for value in data.values():
            if isinstance(value, (dict, list)):
                result = find_token_recursively(value)
                if result:
                    return result
    elif isinstance(data, list):
        for item in data:
            result = find_token_recursively(item)
            if result:
                return result
    return None


def find_token_recursively_with_path(data, path=""):
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
            current_path = f"{path}[{index}]" if path else f"[{index}]"
            result = find_token_recursively_with_path(item, current_path)
            if result:
                return result
    return None


def get_set_cookie_headers(response):
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers and hasattr(raw_headers, "get_all"):
        values = raw_headers.get_all("Set-Cookie")
        if values:
            return list(values)

    header_value = response.headers.get("Set-Cookie", "")
    return [header_value] if header_value else []


def parse_set_cookie_headers(set_cookie_headers):
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


def jwt_debug_summary(token: str) -> str:
    try:
        parts = str(token).split(".")
        if len(parts) < 2:
            return "not-jwt"
        payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("utf-8")).decode("utf-8"))
        safe_claims = {
            key: payload.get(key)
            for key in ["sub", "auth", "role", "roles", "scope", "iss", "aud", "iat", "exp"]
            if key in payload
        }
        fingerprint = hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:12]
        return f"fingerprint={fingerprint}, claims={safe_claims}"
    except Exception as exc:
        return f"jwt-debug-failed: {exc}"


def extract_token_with_source_from_response(response, token_field: str = "") -> tuple[str, dict]:
    if token_field and token_field.strip():
        field = token_field.strip()

        if field.startswith("cookie.") or field.startswith("cookies."):
            cookie_name = field.split(".", 1)[1]
            token = response.cookies.get(cookie_name)
            if not token:
                raise ValueError(f"Response cookie '{cookie_name}' was not found.")
            return str(token), {"source": "cookie", "field": cookie_name}

        try:
            data = response.json()
            token = data
            for key in field.split("."):
                token = token.get(key)
                if not token:
                    raise ValueError(f"Response JSON field '{field}' was not found.")
            return str(token), {"source": "json", "field": field}
        except Exception as json_err:
            raise ValueError(f"Failed to parse configured token field '{field}': {json_err}")

    for header_name in ["Authorization", "X-Auth-Token", "token", "access-token"]:
        header_val = response.headers.get(header_name, response.headers.get(header_name.lower(), ""))
        if header_val:
            if "bearer " in header_val.lower():
                return header_val.split(None, 1)[1], {"source": "header", "field": header_name}
            return header_val, {"source": "header", "field": header_name}

    try:
        detected = find_token_recursively_with_path(response.json())
        if detected:
            detected_token, detected_path = detected
            if detected_token.lower().startswith("bearer "):
                return detected_token.split(None, 1)[1], {"source": "json", "field": detected_path}
            return detected_token, {"source": "json", "field": detected_path}
    except Exception:
        pass

    for cookie_name in ["accessToken", "access_token", "jwt", "token", "session", "sid", "jsessionid"]:
        token_val = response.cookies.get(cookie_name)
        if token_val:
            return str(token_val), {"source": "cookie", "field": cookie_name}

    if response.cookies:
        for cookie in response.cookies:
            return str(cookie.value), {"source": "cookie", "field": cookie.name}

    raise ValueError(
        "Login succeeded, but no token was found in the response body, headers, or cookies. "
        "Set Token Field to an explicit path if needed."
    )


def extract_token_from_response(response, token_field: str = "") -> str:
    return extract_token_with_source_from_response(response, token_field)[0]


def extract_auth_context(login_url: str, id_field: str, pw_field: str, token_field: str, user_id: str, user_pw: str) -> dict:
    id_candidates = [id_field.strip()] if id_field and id_field.strip() else [
        "email",
        "username",
        "userid",
        "user_id",
        "loginId",
        "login_id",
        "id",
    ]
    pw_candidates = [pw_field.strip()] if pw_field and pw_field.strip() else ["password", "passwd", "pw", "pass"]

    response = None
    last_error = None

    for fmt in ["json"]:
        for candidate_id in id_candidates:
            for candidate_pw in pw_candidates:
                payload = {candidate_id: user_id, candidate_pw: user_pw}
                try:
                    if fmt == "json":
                        res = requests.post(login_url, json=payload, timeout=8)
                    else:
                        res = requests.post(login_url, data=payload, timeout=8)

                    print(
                        f"[Auth] login attempt -> {fmt} | ID field: {candidate_id} | "
                        f"PW field: {candidate_pw} | status: {res.status_code}"
                    )
                    if res.ok:
                        response = res
                        print(f"[Auth] login success: {fmt}, ID field: {candidate_id}, PW field: {candidate_pw}")
                        break

                    last_error = f"HTTP {res.status_code} - Body: {res.text[:200]}"
                    print(f"[Auth] login failed: {last_error}")
                except Exception as exc:
                    last_error = f"Connection/Network Error: {exc}"
                    print(f"[Auth] login exception: {last_error}")
            if response:
                break
        if response:
            break

    if not response:
        raise Exception(f"All login attempts failed. Last error: {last_error}")

    token, token_meta = extract_token_with_source_from_response(response, token_field)
    token_field_suffix = f".{token_meta.get('field', '')}" if token_meta.get("field") else ""
    print(
        f"[Auth] extracted token source={token_meta.get('source', '')}{token_field_suffix}; "
        f"{jwt_debug_summary(token)}"
    )
    set_cookie_headers = get_set_cookie_headers(response)
    cookies, cookie_attrs = parse_set_cookie_headers(set_cookie_headers)
    if not cookies:
        cookies = {cookie.name: cookie.value for cookie in response.cookies}
        cookie_attrs = {cookie.name: {} for cookie in response.cookies}

    return {
        "token": token,
        "token_source": token_meta.get("source", ""),
        "token_field": token_meta.get("field", ""),
        "cookies": cookies,
        "cookie_attrs": cookie_attrs,
        "set_cookie_headers": set_cookie_headers,
        "login_status_code": response.status_code,
    }


def extract_token(login_url: str, id_field: str, pw_field: str, token_field: str, user_id: str, user_pw: str) -> str:
    return extract_auth_context(login_url, id_field, pw_field, token_field, user_id, user_pw)["token"]
