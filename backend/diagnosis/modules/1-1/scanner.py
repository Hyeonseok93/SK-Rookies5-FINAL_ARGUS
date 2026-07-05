"""ARGUS 1-1 scanner orchestration.

The 1-1 module owns the scan loop.  It can be called by the ARGUS diagnosis
runtime through ``run_g11_scan()`` or by the development web UI through the
compatibility ``run_zap_scan()`` function at the bottom of this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import urlparse

import requests


_MODULE_DIR = Path(__file__).resolve().parent


def _load_sibling(name: str):
    spec = importlib.util.spec_from_file_location(f"diag_g11_{name}", _MODULE_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load {name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


auth = _load_sibling("auth")
openapi_utils = _load_sibling("openapi_utils")
payloads = _load_sibling("payloads")
rules = _load_sibling("rules")
zap_adapter = _load_sibling("zap_adapter")
zap_runner = _load_sibling("zap_runner")


scan_status = {
    "is_running": False,
    "progress": 0,
    "message": "Ready",
    "result_file": None,
    "log_file": None,
    "total_alerts": 0,
}


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


@dataclass
class ScanResult:
    status: str
    findings: list[Any] = field(default_factory=list)
    message: str = ""


def _short_payload(value: str, limit: int = 80) -> str:
    text = str(value or "").replace("\n", "\\n").replace("\r", "\\r")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _log(message: str) -> None:
    print(message, flush=True)


def update_status(is_running=None, progress=None, message=None, result_file=None, log_file=None, total_alerts=None):
    if is_running is not None:
        scan_status["is_running"] = is_running
    if progress is not None:
        scan_status["progress"] = progress
    if message is not None:
        scan_status["message"] = message
    if result_file is not None:
        scan_status["result_file"] = result_file
    if log_file is not None:
        scan_status["log_file"] = log_file
    if total_alerts is not None:
        scan_status["total_alerts"] = total_alerts
    try:
        from app.services import diagnosis_progress as dp

        if is_running is False:
            if progress == 100:
                dp.finish(message or "1-1 scan completed")
            elif message:
                dp.fail(message)
        else:
            dp.update(
                phase="running",
                message=message,
                percent=progress,
            )
    except Exception:
        pass


def _read_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_api_tree(data_dir: Path):
    for name in ["api-tree-verified.json", "api-tree-ready.json", "api-tree.json"]:
        value = _read_json(data_dir / name)
        if value:
            return value, name
    return None, ""


def _format_request(req_obj) -> str:
    headers = "\n".join(f"  {k}: {v}" for k, v in getattr(req_obj, "headers", {}).items())
    body = getattr(req_obj, "body", b"") or b""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    return f"{getattr(req_obj, 'method', '')} {getattr(req_obj, 'url', '')}\n\nHeaders:\n{headers}\n\nBody:\n{body}"


def _format_response(res) -> str:
    headers = "\n".join(f"  {k}: {v}" for k, v in res.headers.items())
    body = res.text or ""
    if len(body) > 1600:
        body = body[:1600] + "\n... truncated ..."
    return f"HTTP/1.1 {res.status_code} {res.reason}\n\nHeaders:\n{headers}\n\nBody:\n{body}"


def _normalize_endpoint_path(url_or_path: str, base_url: str) -> str:
    value = str(url_or_path or "").strip()
    if not value:
        return "/"
    if value.startswith("http://") or value.startswith("https://"):
        value = urlparse(value).path or "/"
    elif value.startswith(base_url):
        value = value[len(base_url):] or "/"
    return value.split("?", 1)[0] or "/"


def _merge_components(target: dict, source: dict) -> None:
    for comp_type, comp_value in (source or {}).items():
        if isinstance(comp_value, dict):
            target.setdefault(comp_type, {}).update(comp_value)


def _load_openapi_spec(spec: str, base_url: str, zap=None) -> tuple[dict, dict]:
    endpoints: dict[str, dict] = {}
    components: dict[str, dict] = {}
    for item in [s.strip() for s in str(spec or "").replace(",", "\n").splitlines() if s.strip()]:
        data = None
        try:
            if item.startswith(("http://", "https://")):
                if zap:
                    try:
                        zap.openapi.import_url(item, base_url)
                    except Exception:
                        pass
                res = requests.get(item, timeout=8)
                if res.ok:
                    data = res.json()
            else:
                path = Path(item)
                if path.is_file():
                    if zap:
                        try:
                            zap.openapi.import_file(str(path.resolve()), base_url)
                        except Exception:
                            pass
                    data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[OpenAPI] failed to load {item}: {exc}")
        if not isinstance(data, dict):
            continue
        for ep_path, methods in (data.get("paths") or {}).items():
            endpoints.setdefault(ep_path, {})
            for method, details in (methods or {}).items():
                if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    endpoints[ep_path][method.lower()] = details or {}
        _merge_components(components, data.get("components") or {})
    return endpoints, components


def _build_endpoints_for_account(account: dict, target_url: str, zap=None) -> tuple[dict, dict]:
    base_url = account.get("base_url", target_url).rstrip("/")
    endpoints, components = _load_openapi_spec(account.get("openapi_url", ""), base_url, zap)

    for raw in str(account.get("url_list_str", "") or "").splitlines():
        path = _normalize_endpoint_path(raw, base_url)
        if path:
            endpoints.setdefault(path, {}).setdefault("get", {"parameters": [], "responses": {}})

    for raw in str(account.get("api_list_str", "") or "").splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) != 2:
            continue
        method, raw_path = parts
        path = _normalize_endpoint_path(raw_path, base_url)
        endpoints.setdefault(path, {})[method.lower()] = {"parameters": [], "responses": {}}

    return endpoints, components


def _base_key(url: str) -> str:
    return str(url or "").strip().rstrip("/").lower()


def _schema_from_api_tree_param(param: dict) -> dict:
    schema = param.get("schema")
    if isinstance(schema, dict) and schema:
        return schema
    raw_type = str(param.get("type") or "string").lower()
    if raw_type in {"int", "integer", "long"}:
        schema = {"type": "integer"}
    elif raw_type in {"float", "double", "number"}:
        schema = {"type": "number"}
    elif raw_type in {"bool", "boolean"}:
        schema = {"type": "boolean"}
    elif raw_type in {"list", "array"}:
        schema = {"type": "array", "items": {"type": "string"}}
    elif raw_type == "object":
        schema = {"type": "object", "properties": {}}
    else:
        schema = {"type": "string"}
    if param.get("sample") not in (None, ""):
        schema["example"] = param.get("sample")
    return schema


def _looks_like_file_field(name: str, schema: dict | None = None) -> bool:
    field = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    schema = schema or {}
    schema_type = str(schema.get("type") or "").lower()
    schema_format = str(schema.get("format") or "").lower()
    items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
    item_format = str(items.get("format") or "").lower()
    if schema_type == "string" and schema_format == "binary":
        return True
    if schema_type == "array" and item_format == "binary":
        return True
    return any(token in field for token in ["image", "images", "photo", "photos", "file", "files", "upload", "attachment"])


def _api_tree_endpoint_to_openapi_detail(ep: dict) -> dict:
    detail = ep.get("openapi")
    if isinstance(detail, dict) and (detail.get("parameters") or detail.get("requestBody")):
        return detail

    detail = dict(detail or {})
    parameters = list(detail.get("parameters") or [])
    json_properties: dict[str, dict] = {}
    json_required: list[str] = []
    form_properties: dict[str, dict] = {}
    form_required: list[str] = []
    request_header_content_types = {
        str(header.get("sample") or header.get("value") or "").lower()
        for header in ep.get("request_headers", []) or []
        if str(header.get("name") or "").lower() == "content-type"
    }
    prefers_multipart = any("multipart/form-data" in value for value in request_header_content_types)

    for param in ep.get("request_params", []) or []:
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        if not name:
            continue
        location = str(param.get("in") or param.get("location") or "query").lower()
        schema = _schema_from_api_tree_param(param)
        required = bool(param.get("required", False))
        if location in {"query", "path", "header", "cookie"}:
            parameters.append({"name": name, "in": location, "required": required, "schema": schema})
        elif location in {"body", "json"} and not prefers_multipart:
            json_properties[name] = schema
            if required:
                json_required.append(name)
        elif location in {"body", "form", "formdata", "multipart"}:
            if prefers_multipart and _looks_like_file_field(name, schema):
                schema = {"type": "array", "items": {"type": "string", "format": "binary"}}
            form_properties[name] = schema
            if required:
                form_required.append(name)

    if parameters:
        detail["parameters"] = parameters

    content = ((detail.get("requestBody") or {}).get("content") or {}).copy()
    if json_properties and "application/json" not in content:
        json_schema = {"type": "object", "properties": json_properties}
        if json_required:
            json_schema["required"] = json_required
        content["application/json"] = {"schema": json_schema}
    if form_properties and "multipart/form-data" not in content:
        form_schema = {"type": "object", "properties": form_properties}
        if form_required:
            form_schema["required"] = form_required
        content["multipart/form-data"] = {"schema": form_schema}
    if content:
        detail["requestBody"] = {"content": content}

    detail.setdefault("responses", {})
    return detail


def _endpoints_by_base_from_api_tree(
    api_tree: Any,
    allowed_base_urls: list[str] | None = None,
) -> tuple[dict[str, dict], dict]:
    grouped: dict[str, dict] = {}
    if not isinstance(api_tree, dict):
        return grouped, {}
    allowed = {_base_key(u) for u in allowed_base_urls or [] if str(u or "").strip()}
    canonical = {_base_key(u): str(u).strip().rstrip("/") for u in allowed_base_urls or []}
    for ep in api_tree.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        raw_base = str(ep.get("base_url") or "").strip().rstrip("/")
        base_key = _base_key(raw_base)
        if allowed and base_key not in allowed:
            continue
        base_url = canonical.get(base_key, raw_base)
        if not base_url:
            continue
        path = ep.get("path") or ep.get("url") or ep.get("endpoint")
        method = str(ep.get("method") or "GET").lower()
        if path:
            grouped.setdefault(base_url, {}).setdefault(_normalize_endpoint_path(path, base_url), {})[method] = _api_tree_endpoint_to_openapi_detail(ep)
    return grouped, api_tree.get("components") or {}


def _build_auth_headers_for_mode(account: dict, mode: str | None = None) -> dict:
    token = account.get("token")
    headers = auth.build_auth_headers(token, account, mode)
    clean_token = str(token or "").replace("Bearer ", "").strip()
    if mode == "authorization_raw" and clean_token:
        headers["Authorization"] = clean_token
    elif mode == "x_auth_token" and clean_token:
        headers.pop("Authorization", None)
        headers["X-Auth-Token"] = clean_token
    elif mode == "access_token_header" and clean_token:
        headers.pop("Authorization", None)
        headers["access-token"] = clean_token
    elif mode == "access_token_camel_header" and clean_token:
        headers.pop("Authorization", None)
        headers["accessToken"] = clean_token
    return headers


def _authorization_headers_from_account(account: dict) -> dict:
    current = dict(_build_auth_headers_for_mode(account, account.get("auth_mode")))
    current.pop("Cookie", None)
    current.pop("cookie", None)
    if current:
        return current
    for mode in ["header", "authorization_raw", "x_auth_token", "access_token_header", "access_token_camel_header"]:
        headers = dict(_build_auth_headers_for_mode(account, mode))
        headers.pop("Cookie", None)
        headers.pop("cookie", None)
        if headers:
            return headers
    return {}


def _cookie_header_and_source(account: dict) -> tuple[str, str]:
    cookie_header = auth.build_cookie_header_from_account(account)
    if cookie_header:
        return cookie_header, "real"
    token = str(account.get("token") or "").replace("Bearer ", "").strip()
    if token:
        cookie_name = str(account.get("token_field") or "accessToken").split(".")[-1] or "accessToken"
        return f"{cookie_name}={token}", "synthetic"
    return "", "none"


def _classify_auth_acceptance(
    account: dict,
    url: str,
    method: str,
    params: dict | None = None,
    json_body: dict | None = None,
    files=None,
) -> dict:
    authz_headers = _authorization_headers_from_account(account)
    cookie_header, cookie_source = _cookie_header_and_source(account)
    probes = {
        "no_auth": {},
        "header_only": dict(authz_headers),
        "cookie_only": {"Cookie": cookie_header} if cookie_header else {},
        "both": {**authz_headers, **({"Cookie": cookie_header} if cookie_header else {})},
    }
    statuses: dict[str, int | None] = {}
    errors: dict[str, str] = {}
    for name, probe_headers in probes.items():
        try:
            res = requests.request(
                method,
                url,
                headers=probe_headers or None,
                params=params or None,
                json=json_body or None,
                files=files,
                timeout=6,
            )
            statuses[name] = res.status_code
        except Exception as exc:
            statuses[name] = None
            errors[name] = str(exc)

    def ok(name: str) -> bool:
        return _is_successful_response(statuses.get(name) or 0)

    if ok("no_auth"):
        mode = "PUBLIC_OR_BROKEN"
    elif ok("header_only") and not ok("cookie_only"):
        mode = "HEADER_ONLY"
    elif ok("cookie_only") and not ok("header_only"):
        mode = "COOKIE_ONLY"
    elif ok("header_only") and ok("cookie_only"):
        mode = "HEADER_OR_COOKIE"
    elif ok("both") and not ok("header_only") and not ok("cookie_only"):
        mode = "HEADER_AND_COOKIE"
    elif any(value is None for value in statuses.values()):
        mode = "UNKNOWN"
    else:
        mode = "UNKNOWN"

    result = {"mode": mode, "statuses": statuses, "cookie_source": cookie_source}
    if errors:
        result["errors"] = errors
    return result


def _auth_probe_paths(endpoints: dict, account: dict) -> list[str]:
    excluded = ["login", "signup", "register", "refresh", "logout", "reset-password"]
    preferred = ["me", "profile", "account", "user", "member", "dashboard", "order", "reservation"]
    if auth.is_admin_account(account):
        preferred = ["admin", "dashboard", "member", "user", "reservation", "report", "me", "profile"]
    paths = []
    for ep_path, methods in endpoints.items():
        lowered = ep_path.lower()
        if "get" not in methods or "{" in ep_path or any(x in lowered for x in excluded):
            continue
        if auth.is_admin_account(account) and "admin" not in lowered:
            continue
        if not auth.is_admin_account(account) and "admin" in lowered:
            continue
        if any(x in lowered for x in preferred):
            paths.append(ep_path)
    for ep_path, methods in endpoints.items():
        if len(paths) >= 12:
            break
        lowered = ep_path.lower()
        if "get" in methods and "{" not in ep_path and not any(x in lowered for x in excluded) and ep_path not in paths:
            paths.append(ep_path)
    return paths[:12]


def _detect_account_auth_mode(account: dict, target_url: str) -> str:
    candidates = _auth_probe_paths(account.get("validated_endpoints", {}), account)
    if not candidates:
        return "cookie" if auth.build_cookie_header_from_account(account) else "header"
    base_url = account.get("base_url", target_url).rstrip("/")
    modes = ["header", "cookie", "both", "authorization_raw", "x_auth_token", "access_token_header", "access_token_camel_header"]
    if (account.get("token_source") or "").lower() == "cookie":
        modes = ["cookie", "both", "header"]
    for mode in modes:
        headers = _build_auth_headers_for_mode(account, mode)
        if not headers:
            continue
        for path in candidates:
            url = f"{base_url}{path}"
            try:
                no_auth = requests.get(url, timeout=4)
                with_auth = requests.get(url, headers=headers, timeout=4)
            except Exception:
                continue
            if 200 <= with_auth.status_code < 400 and no_auth.status_code in {401, 403}:
                print(f"[AuthMode] {account.get('role', 'account')}: verified {mode} on {url}")
                return mode
            if 200 <= with_auth.status_code < 400:
                return mode
    account["auth_unverified"] = True
    return "disabled"


def _account_role_text(account: dict | None) -> str:
    account = account or {}
    return " ".join(
        str(value or "").lower()
        for value in [
            account.get("role"),
            account.get("base_url"),
            account.get("claims", {}),
            account.get("email"),
        ]
    )


def _endpoint_role_priority(path: str, account: dict | None) -> tuple[int, str]:
    lowered = str(path or "").lower()
    role_text = _account_role_text(account)
    is_admin = "admin" in role_text
    is_seller = "seller" in role_text
    if is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
        return (0, lowered)
    if is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
        return (0, lowered)
    if not is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
        return (3, lowered)
    if not is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
        return (3, lowered)
    return (1, lowered)


def _resolved_paths(path: str) -> list[str]:
    if "{" not in path:
        return [path]
    return [re.sub(r"\{[^}]+\}", "1", path)]


def _is_mutation(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


def _is_protected_mutation(path: str, method: str) -> tuple[bool, str]:
    lowered = path.lower()
    if method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False, ""
    account_markers = ["logout", "password", "profile", "/me", "withdraw", "delete-account"]
    state_markers = ["close", "reopen", "restore", "status", "approve", "reject", "cancel", "payment"]
    if any(x in lowered for x in account_markers):
        return True, "account/session/profile mutation is protected from active scanning"
    if any(x in lowered for x in state_markers):
        return True, "state-transition endpoint is protected from active scanning"
    return False, ""


def _request_defaults(details: dict, components: dict) -> tuple[dict, dict, dict, list[str], dict, bool, list[str]]:
    params = {}
    param_schemas = {}
    json_body = {}
    json_keypaths: list[str] = []
    json_schemas = {}
    multipart = False
    multipart_file_keys: list[str] = []

    for param in details.get("parameters", []) or []:
        if not isinstance(param, dict) or param.get("in", "query") != "query":
            continue
        name = param.get("name")
        schema = param.get("schema") or {}
        if not name:
            continue
        params[name] = openapi_utils.default_value_for_query_param(name, schema, components)
        if openapi_utils.is_xss_injectable_schema(schema, name, components):
            param_schemas[name] = openapi_utils.resolve_schema_ref(schema, components)

    content = ((details.get("requestBody") or {}).get("content") or {})
    if "multipart/form-data" in content:
        multipart = True
        schema = openapi_utils.resolve_schema_ref(content["multipart/form-data"].get("schema") or {}, components)
        for name, prop in (schema.get("properties") or {}).items():
            prop_type = openapi_utils.get_schema_type(prop, components)
            item_schema = openapi_utils.resolve_schema_ref(prop.get("items", {}), components)
            item_format = (item_schema.get("format") or "").lower() if isinstance(item_schema, dict) else ""
            if _looks_like_file_field(name, prop):
                multipart_file_keys.append(name)
    elif "application/json" in content:
        schema = openapi_utils.resolve_schema_ref(content["application/json"].get("schema") or {}, components)
        json_body = openapi_utils.build_default_payload_from_schema(schema, components)
        json_keypaths = openapi_utils.extract_injectable_keypaths(schema, components=components)
        json_schemas = {kp: openapi_utils.schema_for_keypath(schema, kp, components) for kp in json_keypaths}

    return params, param_schemas, json_body, json_keypaths, json_schemas, multipart, multipart_file_keys


def _alert_from_xss(result: dict, method: str, url: str, param: str, payload: str, res, account_role: str) -> dict:
    return {
        "alert": "Reflected Cross Site Scripting",
        "url": url,
        "method": method.upper(),
        "risk": result.get("risk", "High"),
        "confidence": result.get("confidence", "High"),
        "param": param,
        "attack": payload,
        "status_code": res.status_code,
        "evidence": result.get("evidence", ""),
        "custom_type": result.get("custom_type", "40012"),
        "account_role": account_role,
        "evidence_request": _format_request(res.request),
        "evidence_response": _format_response(res),
        "successful_attack_payloads": [payload],
        "description": "Response reflected an executable XSS payload.",
        "solution": "Escape untrusted output by context and reject executable markup in API input.",
    }


def _alert_from_header(url: str, method: str, item: dict, res, account_role: str) -> dict:
    return {
        "alert": item["message"],
        "url": url,
        "method": method.upper(),
        "risk": "Medium",
        "confidence": "High",
        "param": item["rule_id"],
        "attack": "",
        "status_code": res.status_code,
        "evidence": item["message"],
        "custom_type": item["rule_id"],
        "account_role": account_role,
        "evidence_request": _format_request(res.request),
        "evidence_response": _format_response(res),
    }


def _is_successful_response(status_code: int) -> bool:
    return 200 <= int(status_code or 0) < 400


def _csrf_alert(method: str, url: str, name: str, param: str, res, account_role: str, auth_acceptance: dict | None = None) -> dict:
    auth_acceptance = auth_acceptance or {}
    return {
        "alert": name,
        "url": url,
        "method": method.upper(),
        "risk": "High",
        "confidence": "Medium",
        "param": param,
        "attack": param,
        "status_code": res.status_code,
        "evidence": f"Request was accepted with {param}.",
        "custom_type": "CSRF_CUSTOM",
        "account_role": account_role,
        "evidence_request": _format_request(res.request),
        "evidence_response": _format_response(res),
        "auth_acceptance_mode": auth_acceptance.get("mode", ""),
        "auth_acceptance_statuses": auth_acceptance.get("statuses", {}),
        "cookie_source": auth_acceptance.get("cookie_source", "none"),
        "description": "State-changing request may be accepted without strong Origin/CSRF validation.",
        "solution": "Require server-side CSRF tokens or strict Origin/Referer checks for cookie-authenticated mutations.",
    }


def _normalized_group_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    path = parsed.path if parsed.scheme else str(url or "").split("?", 1)[0]
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path or "/")
    if parsed.scheme:
        host = parsed.netloc
        return f"{parsed.scheme}://{host}{path}"
    return path


def _group_alerts(alerts: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    global_types = {
        "REFERRER_POLICY_CUSTOM",
        "PERMISSIONS_POLICY_CUSTOM",
        "X_FRAME_OPTIONS_CUSTOM",
        "HSTS_CUSTOM",
        "MIME_SNIFF_CUSTOM",
        "CSP_CUSTOM",
        "CORS_ORIGIN_REFLECTION",
    }
    endpoint_grouped_types = {"40012", "40014", "40016", "40017", "DOM_XSS_SUSPECT", "CSRF_CUSTOM"}
    for alert in alerts:
        key_id = alert.get("custom_type") or alert.get("pluginId") or alert.get("alert", "")
        normalized_url = _normalized_group_url(alert.get("url", ""))
        if key_id in global_types:
            key = f"GLOBAL_{key_id}"
        elif key_id in endpoint_grouped_types:
            key = f"{alert.get('account_role', '')}:{alert.get('method', '')}:{normalized_url}:{key_id}"
        else:
            key = f"{alert.get('account_role', '')}:{alert.get('method', '')}:{normalized_url}:{key_id}:{alert.get('param', '')}"
        current_url = f"{alert.get('method', 'GET')} {alert.get('url', '')}"
        if key not in grouped:
            grouped[key] = dict(alert)
            grouped[key]["occurrence_count"] = 1
            grouped[key]["affected_urls"] = [current_url]
            grouped[key]["affected_parameters"] = [alert.get("param", "")] if alert.get("param") else []
            grouped[key]["account_roles"] = [alert.get("account_role", "")] if alert.get("account_role") else []
            if alert.get("attack") and alert["attack"] not in grouped[key].get("successful_attack_payloads", []):
                grouped[key]["successful_attack_payloads"] = grouped[key].get("successful_attack_payloads", []) + [alert["attack"]]
            continue
        item = grouped[key]
        item["occurrence_count"] += 1
        if current_url not in item["affected_urls"]:
            item["affected_urls"].append(current_url)
        param = alert.get("param")
        if param and param not in item["affected_parameters"]:
            item["affected_parameters"].append(param)
        role = alert.get("account_role")
        if role and role not in item["account_roles"]:
            item["account_roles"].append(role)
        payloads_seen = set(item.get("successful_attack_payloads", []))
        payloads_seen.update(alert.get("successful_attack_payloads", []))
        if alert.get("attack"):
            payloads_seen.add(alert["attack"])
        item["successful_attack_payloads"] = sorted(payloads_seen)
    return list(grouped.values())


def _map_alerts(alerts: list[dict]) -> list[dict]:
    mapped = []
    type_names = {
        "40012": ("1-1-XSS-REFLECTED", "Reflected XSS", "High"),
        "40014": ("1-1-XSS-STORED", "Stored XSS", "High"),
        "40016": ("1-1-XSS-PERSISTENT", "Persistent XSS", "High"),
        "40017": ("1-1-XSS-CROSS-ROLE", "Cross-Role Stored XSS", "High"),
        "DOM_XSS_SUSPECT": ("1-1-XSS-DOM", "DOM XSS Suspect", "Low"),
        "CSRF_CUSTOM": ("1-1-CSRF", "CSRF", "High"),
        "CORS_ORIGIN_REFLECTION": ("1-1-CORS", "CORS Origin Reflection", "High"),
        "CSP_CUSTOM": ("1-1-HEADER-CSP", "Missing Security Header", "Medium"),
        "MIME_SNIFF_CUSTOM": ("1-1-HEADER-NOSNIFF", "Missing Security Header", "Medium"),
        "X_FRAME_OPTIONS_CUSTOM": ("1-1-HEADER-XFO", "Missing Security Header", "Medium"),
        "REFERRER_POLICY_CUSTOM": ("1-1-HEADER-REFERRER", "Missing Security Header", "Medium"),
        "PERMISSIONS_POLICY_CUSTOM": ("1-1-HEADER-PERMISSIONS", "Missing Security Header", "Medium"),
        "HSTS_CUSTOM": ("1-1-HEADER-HSTS", "Missing Security Header", "Medium"),
    }
    for alert in alerts:
        key_id = alert.get("custom_type") or alert.get("pluginId") or ""
        vuln_id, vuln_type, severity = type_names.get(key_id, (f"1-1-{key_id or 'ZAP'}", alert.get("alert", "Security Finding"), alert.get("risk", "Medium")))
        mapped.append({
            "vuln_id": vuln_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "vuln_description": alert.get("description") or alert.get("alert", ""),
            "validation_status": "True Positive" if key_id != "DOM_XSS_SUSPECT" else "Suspected",
            "validation_reason": "Verified by the ARGUS 1-1 backend scanner.",
            "alert": alert.get("alert", ""),
            "url": alert.get("url", ""),
            "method": alert.get("method", "GET"),
            "risk": alert.get("risk", severity),
            "confidence": alert.get("confidence", "Medium"),
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "status_code": alert.get("status_code", 0),
            "evidence": alert.get("evidence", ""),
            "evidence_request": alert.get("evidence_request", ""),
            "evidence_response": alert.get("evidence_response", ""),
            "description": alert.get("description", ""),
            "occurrence_count": alert.get("occurrence_count", 1),
            "account_role": alert.get("account_role", ""),
            "account_roles": alert.get("account_roles", []),
            "affected_parameters": alert.get("affected_parameters", []),
            "affected_urls": alert.get("affected_urls", []),
            "successful_attack_payloads": alert.get("successful_attack_payloads", []),
            "auth_acceptance_mode": alert.get("auth_acceptance_mode", ""),
            "auth_acceptance_statuses": alert.get("auth_acceptance_statuses", {}),
            "cookie_source": alert.get("cookie_source", ""),
            "cross_account_writer_role": alert.get("cross_account_writer_role", ""),
            "cross_account_reader_role": alert.get("cross_account_reader_role", ""),
            "cross_account_write_url": alert.get("cross_account_write_url", ""),
            "cross_account_read_url": alert.get("cross_account_read_url", ""),
            "remediation_summary": alert.get("solution", ""),
            "remediation_cause": "",
            "remediation_guide": alert.get("solution", ""),
            "remediation_code": "",
        })
    return mapped


def _write_reports(findings: list[dict], result_dir: Path, role: str = "web_ui") -> str:
    result_dir.mkdir(parents=True, exist_ok=True)
    summary = result_dir / f"zap_report_summary_{role}.json"
    summary.write_text(json.dumps(findings, ensure_ascii=False, indent=4), encoding="utf-8")
    filtered = result_dir / f"zap_report_summary_{role}_filtered.jsonc"
    meaningful = [a for a in findings if a.get("severity") != "-" and a.get("risk") != "False Positive"]
    lines = [
        "// =====================================================================",
        "// ARGUS 1-1 scan result report - filtered JSONC",
        f"// total findings: {len(meaningful)}",
        "// =====================================================================",
        json.dumps(meaningful, ensure_ascii=False, indent=4),
        "",
    ]
    filtered.write_text("\n".join(lines), encoding="utf-8")
    return str(summary)


def _scan_accounts(target_url: str, auth_tokens: list[dict], zap=None) -> list[dict]:
    accounts = auth_tokens or [{"role": "anonymous", "token": None, "base_url": target_url}]
    for account in accounts:
        if account.get("token") and not account.get("claims"):
            _, claims = auth.decode_jwt_claims(account.get("token"))
            account["claims"] = claims
        endpoints, components = _build_endpoints_for_account(account, target_url, zap)
        account["validated_endpoints"] = account.get("validated_endpoints") or endpoints
        account["swagger_components"] = account.get("swagger_components") or components
        if account.get("token") or account.get("cookies"):
            account["auth_mode"] = _detect_account_auth_mode(account, target_url)
    verified = [a for a in accounts if not a.get("auth_unverified")]
    if auth_tokens and not verified:
        raise RuntimeError("No authenticated account could be verified; scan stopped to avoid unsafe fallback requests.")
    return verified


def scan_target(target_url: str, auth_tokens: list[dict] | None = None, result_dir: Path | None = None, endpoints: dict | None = None, components: dict | None = None) -> list[dict]:
    update_status(is_running=True, progress=0, message="ARGUS 1-1 backend scanner starting", result_file=None, total_alerts=0)
    auth_tokens = auth_tokens or []
    result_dir = result_dir or Path("scanner_app/results")
    _log(f"[G11] scan starting target={target_url.rstrip('/')} accounts={len(auth_tokens) or 1}")

    zap = None
    for port in [8889, 8090]:
        try:
            zap = zap_adapter.connect_zap(f"http://127.0.0.1:{port}")
            zap.core.version
            _log(f"[ZAP] connected on port {port}")
            break
        except Exception:
            zap = None

    accounts = _scan_accounts(target_url.rstrip("/"), auth_tokens, zap)
    if endpoints:
        for account in accounts:
            account.setdefault("validated_endpoints", {}).update(endpoints)
            account.setdefault("swagger_components", {}).update(components or {})

    alerts: list[dict] = []
    update_status(progress=10, message="Endpoint scan started")

    total = sum(len(a.get("validated_endpoints", {})) for a in accounts) or 1
    done = 0
    for account in accounts:
        role = account.get("role", "anonymous")
        base_url = account.get("base_url", target_url).rstrip("/")
        headers = _build_auth_headers_for_mode(account, account.get("auth_mode"))
        _log(f"[G11] account role={role} base={base_url} auth_mode={account.get('auth_mode') or 'anonymous'}")
        if zap and account is accounts[0]:
            zap_adapter.apply_auth_to_zap(zap, account.get("token"), auth.build_cookie_header_from_account(account))

        ordered_endpoints = sorted(
            (account.get("validated_endpoints") or {}).items(),
            key=lambda item: _endpoint_role_priority(item[0], account),
        )
        for path, methods in ordered_endpoints:
            done += 1
            update_status(progress=min(85, 10 + int(done / total * 75)), message=f"Scanning {role} {path}")
            for method, details in (methods or {}).items():
                method = method.upper()
                skip, reason = _is_protected_mutation(path, method)
                if skip:
                    _log(f"[Safety] skip {method} {path}: {reason}")
                    continue
                for resolved_path in _resolved_paths(path):
                    url = f"{base_url}/{resolved_path.lstrip('/')}"
                    params, param_schemas, json_body, json_keypaths, json_schemas, multipart, file_keys = _request_defaults(details or {}, account.get("swagger_components", {}))
                    files = {key: ("", b"", "application/octet-stream") for key in file_keys} if file_keys else None
                    _log(
                        f"[G11] endpoint {done}/{total} {role} {method} {url} "
                        f"query_fields={len(param_schemas)} body_fields={len(json_keypaths)} csrf={'yes' if _is_mutation(method) else 'no'}"
                    )

                    try:
                        baseline = requests.request(method, url, headers=headers, params=params or None, json=json_body or None, files=files, timeout=6)
                    except Exception as exc:
                        _log(f"[Scan] baseline failed {method} {url}: {exc}")
                        continue
                    _log(f"[G11] baseline {method} {url} -> {baseline.status_code}")

                    for header_finding in rules.assess_security_headers(baseline, url.startswith("https://")):
                        alerts.append(_alert_from_header(url, method, header_finding, baseline, role))

                    if baseline.status_code in {401, 403}:
                        _log(f"[G11] skip active XSS/CSRF {method} {url}: baseline auth status {baseline.status_code}")
                        continue

                    for param in param_schemas:
                        trial_count = len(payloads.payloads_for_xss_field(param, param_schemas[param], account.get("swagger_components", {})))
                        _log(f"[XSS] testing query field '{param}' on {method} {url} payloads={trial_count}")
                        for payload in payloads.payloads_for_xss_field(param, param_schemas[param], account.get("swagger_components", {})):
                            test_params = dict(params)
                            test_params[param] = payload
                            try:
                                res = requests.request(method, url, headers=headers, params=test_params, json=json_body or None, files=files, timeout=6)
                            except Exception:
                                continue
                            if not _is_successful_response(res.status_code):
                                continue
                            result = rules.classify_xss_response(payload, res.text, res.headers.get("Content-Type", ""), method, _is_mutation(method), dict(res.headers), baseline.text)
                            if result:
                                _log(
                                    f"[XSS] DETECTED {result.get('kind', 'xss')} {method} {url} "
                                    f"field={param} status={res.status_code} payload={_short_payload(payload)}"
                                )
                                alerts.append(_alert_from_xss(result, method, url, param, payload, res, role))
                                break

                    for keypath in json_keypaths:
                        trial_count = len(payloads.payloads_for_xss_field(keypath, json_schemas.get(keypath), account.get("swagger_components", {})))
                        _log(f"[XSS] testing body field '{keypath}' on {method} {url} payloads={trial_count}")
                        for payload in payloads.payloads_for_xss_field(keypath, json_schemas.get(keypath), account.get("swagger_components", {})):
                            body = copy.deepcopy(json_body)
                            openapi_utils.set_nested_value_by_keypath(body, keypath, payload)
                            req_headers = dict(headers)
                            req_headers["Content-Type"] = "application/json"
                            try:
                                res = requests.request(method, url, headers=req_headers, params=params or None, json=body, timeout=6)
                            except Exception:
                                continue
                            if not _is_successful_response(res.status_code):
                                continue
                            result = rules.classify_xss_response(payload, res.text, res.headers.get("Content-Type", ""), method, _is_mutation(method), dict(res.headers), baseline.text)
                            if result:
                                _log(
                                    f"[XSS] DETECTED {result.get('kind', 'xss')} {method} {url} "
                                    f"field={keypath} status={res.status_code} payload={_short_payload(payload)}"
                                )
                                alerts.append(_alert_from_xss(result, method, url, keypath, payload, res, role))
                                break

                    if _is_mutation(method):
                        auth_acceptance = _classify_auth_acceptance(account, url, method, params, json_body, files)
                        account["auth_acceptance"] = auth_acceptance
                        acceptance_mode = auth_acceptance.get("mode")
                        cookie_source = auth_acceptance.get("cookie_source", "none")
                        _log(
                            f"[AuthAcceptance] {role} {method} {url} mode={acceptance_mode} "
                            f"statuses={auth_acceptance.get('statuses')} cookie_source={cookie_source}"
                        )
                        if acceptance_mode in {"HEADER_ONLY", "HEADER_AND_COOKIE"}:
                            _log(f"[CSRF] not applicable {method} {url}: auth_acceptance={acceptance_mode}")
                            continue
                        if acceptance_mode == "PUBLIC_OR_BROKEN":
                            _log(f"[CSRF] skip {method} {url}: no_auth succeeded; authentication/authorization issue, not CSRF")
                            continue
                        if acceptance_mode == "UNKNOWN":
                            _log(f"[CSRF] deferred {method} {url}: auth acceptance could not be classified")
                            continue
                        if acceptance_mode not in {"COOKIE_ONLY", "HEADER_OR_COOKIE"}:
                            continue
                        if cookie_source != "real":
                            _log(f"[CSRF] potential only {method} {url}: cookie_source={cookie_source}; not reporting confirmed CSRF")
                            continue
                        cookie_header = auth.build_cookie_header_from_account(account)
                        _log(f"[CSRF] testing {method} {url} origins={len(payloads.CSRF_TEST_ORIGINS)} auth_acceptance={acceptance_mode}")
                        for origin in payloads.CSRF_TEST_ORIGINS:
                            csrf_headers = {"Cookie": cookie_header, "Origin": origin, "Referer": origin + "/csrf.html"}
                            try:
                                res = requests.request(method, url, headers=csrf_headers, json=json_body or {}, timeout=6)
                            except Exception:
                                continue
                            _log(f"[CSRF] origin={origin} {method} {url} -> {res.status_code}")
                            if res.status_code not in {401, 403, 415, 500} and rules.check_csrf_token_absence(res):
                                _log(f"[CSRF] DETECTED {method} {url} origin={origin} status={res.status_code}")
                                alerts.append(_csrf_alert(method, url, "CSRF Origin Verification Defect", "Origin", res, role, auth_acceptance))
                                break

    if zap:
        allowed = {"40012", "40014", "40016", "40017", "90034"}
        for alert in zap_adapter.collect_zap_alerts(zap, target_url):
            if str(alert.get("pluginId", "")) in allowed:
                alerts.append(alert)

    update_status(progress=90, message="Writing scan report")
    findings = _map_alerts(_group_alerts(alerts))
    result_file = _write_reports(findings, result_dir)
    _log(f"[G11] scan completed target={target_url.rstrip('/')} raw_alerts={len(alerts)} findings={len(findings)} result={result_file}")
    update_status(is_running=False, progress=100, message="Scan completed", result_file=result_file, total_alerts=len(findings))
    return findings


def run_g11_scan(ctx, module_dir: Path) -> ScanResult:
    raw_config = getattr(ctx, "raw_config", {}) or {}
    g11_config = raw_config.get("diagnosis_1_1") or raw_config.get("g11") or {}
    target_url = g11_config.get("target_url") or raw_config.get("target_url")
    auth_tokens = g11_config.get("auth_tokens") or raw_config.get("auth_tokens") or []
    data_dir = Path(getattr(ctx, "data_dir", "data"))
    dashboard_base_urls: list[str] = []
    if not target_url and auth_tokens:
        target_url = auth_tokens[0].get("base_url")
    if not target_url:
        try:
            from diagnosis.replay.normalize import collect_probe_base_urls, dedupe_probe_bases

            dashboard_base_urls, _ = dedupe_probe_bases(collect_probe_base_urls(raw_config))
            if dashboard_base_urls:
                target_url = dashboard_base_urls[0]
        except Exception:
            target_url = None
    if not target_url:
        return ScanResult(status="skipped", message="No target_url found for diagnosis 1-1.")
    allowed_base_urls = dashboard_base_urls or [target_url]
    api_tree, source_name = _load_api_tree(data_dir)
    endpoints_by_base, components = _endpoints_by_base_from_api_tree(api_tree, allowed_base_urls) if api_tree else ({}, {})
    if not auth_tokens:
        try:
            from diagnosis.probe_auth import all_account_auths_with_meta

            sessions, _meta = all_account_auths_with_meta(raw_config, data_dir=data_dir, refresh=True)
            auth_tokens = [
                {
                    "role": session.get("role") or session.get("email") or "account",
                    "token": session.get("token") or session.get("access_token"),
                    "base_url": session.get("base_url") or target_url,
                    "cookies": session.get("cookies") or {},
                    "cookie_attrs": session.get("cookie_attrs") or {},
                    "set_cookie_headers": session.get("set_cookie_lines") or [],
                    "login_url": session.get("login_url") or "",
                    "claims": session.get("claims") or {},
                    "token_source": session.get("token_source") or session.get("delivery") or "",
                    "token_field": session.get("token_field") or session.get("cookie_name") or "",
                    "email": session.get("email") or "",
                }
                for session in sessions
                if session.get("token") or session.get("access_token") or session.get("cookies")
            ]
        except Exception:
            auth_tokens = []
    allowed_keys = {_base_key(u) for u in allowed_base_urls if str(u or "").strip()}
    if allowed_keys:
        auth_tokens = [
            dict(account, base_url=account.get("base_url") or target_url)
            for account in auth_tokens
            if _base_key(account.get("base_url") or target_url) in allowed_keys
        ]

    result_dir = Path(getattr(ctx, "report_dir", data_dir / "report" / "1-1"))
    result_dir.mkdir(parents=True, exist_ok=True)
    log_path = result_dir / "g11_scan.log"
    update_status(log_file=str(log_path))

    findings: list[dict] = []
    scan_bases = list(endpoints_by_base) or [target_url]
    with log_path.open("w", encoding="utf-8", errors="replace") as log_stream:
        tee_out = _Tee(sys.stdout, log_stream)
        tee_err = _Tee(sys.stderr, log_stream)
        with contextlib.redirect_stdout(tee_out), contextlib.redirect_stderr(tee_err):
            _log(f"[G11] log_file={log_path}")
            _log(f"[G11] started_at={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
            for base_url in scan_bases:
                base_key = _base_key(base_url)
                base_auth_tokens = [
                    account
                    for account in auth_tokens
                    if _base_key(account.get("base_url") or base_url) == base_key
                ]
                legacy_accounts = base_auth_tokens or [{"role": "anonymous", "token": None, "base_url": base_url}]
                for account in legacy_accounts:
                    account["base_url"] = account.get("base_url") or base_url
                    account["validated_endpoints"] = endpoints_by_base.get(base_url, {}) or account.get("validated_endpoints", {})
                    account["swagger_components"] = components or account.get("swagger_components", {})

                before = Path.cwd()
                previous_result_dir_override = getattr(zap_runner, "result_dir_override", None)
                try:
                    os.chdir(result_dir.parent)
                    zap_runner.scan_status = scan_status
                    zap_runner.result_dir_override = str(result_dir.resolve())
                    zap_runner.run_zap_scan(base_url, legacy_accounts)
                finally:
                    zap_runner.result_dir_override = previous_result_dir_override
                    os.chdir(before)

                result_path = result_dir / "zap_report_summary_web_ui.json"
                if result_path.is_file():
                    try:
                        loaded = json.loads(result_path.read_text(encoding="utf-8"))
                        if isinstance(loaded, list):
                            findings.extend(loaded)
                    except Exception as exc:
                        _log(f"[G11] failed to read legacy result {result_path}: {exc}")
            _log(f"[G11] finished_at={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    source_msg = f" api_tree={source_name}" if source_name else ""
    status = "fail" if findings else "pass"
    return ScanResult(status=status, findings=findings, message=f"1-1 scan completed.{source_msg} findings={len(findings)}")


def run_zap_scan(target_url: str, auth_tokens: list[dict]):
    """Compatibility entrypoint for the development web UI."""
    legacy = zap_runner
    legacy.scan_status = scan_status
    scanner_app_dir = Path(__file__).resolve().parents[4] / "scanner_app"
    previous_cwd = Path.cwd()
    try:
        os.chdir(scanner_app_dir)
        legacy.run_zap_scan(target_url, auth_tokens)
    except Exception as exc:
        import traceback

        traceback.print_exc()
        update_status(is_running=False, message=f"Scan error: {exc}")
    finally:
        os.chdir(previous_cwd)
