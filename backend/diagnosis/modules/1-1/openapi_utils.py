"""OpenAPI and endpoint helpers for ARGUS 1-1."""

from __future__ import annotations

import re
import urllib.parse

def is_sensitive_or_nontext_field(param_name: str = "") -> bool:
    name = str(param_name or "").replace("_", "").replace("-", "").lower()
    blocked_tokens = [
        "password",
        "passwd",
        "secret",
        "token",
        "refresh",
        "access",
        "image",
        "file",
        "upload",
        "avatar",
        "photo",
        "price",
        "amount",
        "count",
        "quantity",
        "date",
        "time",
    ]
    return any(token in name for token in blocked_tokens)


def resolve_schema_ref(schema: dict, components: dict | None = None) -> dict:
    if not isinstance(schema, dict):
        return {}
    if "$ref" not in schema:
        return schema
    ref = schema.get("$ref", "")
    if not ref.startswith("#/components/schemas/") or not components:
        return schema
    name = ref.rsplit("/", 1)[-1]
    return components.get("schemas", {}).get(name, schema)


def get_schema_type(schema: dict, components: dict | None = None) -> str:
    schema = resolve_schema_ref(schema or {}, components)
    if "type" in schema:
        return str(schema["type"])
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "string"


def is_xss_injectable_schema(schema: dict, param_name: str = "", components: dict | None = None) -> bool:
    if is_sensitive_or_nontext_field(param_name):
        return False
    schema_type = get_schema_type(schema or {}, components)
    return schema_type in {"string", "object", "array"}


def extract_injectable_keypaths(schema: dict, prefix: str = "", components: dict | None = None) -> list[str]:
    schema = resolve_schema_ref(schema or {}, components)
    schema_type = get_schema_type(schema, components)
    if schema_type == "string":
        return [prefix] if prefix else []
    if schema_type == "object":
        paths = []
        for key, child_schema in (schema.get("properties") or {}).items():
            child_path = f"{prefix}.{key}" if prefix else key
            paths.extend(extract_injectable_keypaths(child_schema, child_path, components))
        return paths
    if schema_type == "array":
        item_paths = extract_injectable_keypaths(schema.get("items", {}), "", components)
        return [f"{prefix}[0].{path}" if path else f"{prefix}[0]" for path in item_paths]
    return []


def schema_for_keypath(schema: dict, keypath: str, components: dict | None = None) -> dict:
    current = resolve_schema_ref(schema or {}, components)
    for raw_part in keypath.replace("[0]", "").split("."):
        if not raw_part:
            continue
        current = resolve_schema_ref(current, components)
        if get_schema_type(current, components) == "array":
            current = resolve_schema_ref(current.get("items", {}), components)
        current = resolve_schema_ref((current.get("properties") or {}).get(raw_part, {}), components)
    return current


def set_nested_value_by_keypath(target_dict: dict, keypath: str, value) -> dict:
    target = target_dict
    parts = [part for part in keypath.split(".") if part]
    for raw_part in parts[:-1]:
        is_array_part = raw_part.endswith("[0]")
        part = raw_part[:-3] if is_array_part else raw_part
        if is_array_part:
            if part:
                target = target.setdefault(part, [])
            if not isinstance(target, list):
                return target_dict
            while len(target) <= 0:
                target.append({})
            target = target[0]
        else:
            if isinstance(target, list):
                while len(target) <= 0:
                    target.append({})
                target = target[0]
            target = target.setdefault(part, {})

    if not parts:
        return target_dict

    last_raw = parts[-1]
    is_array_last = last_raw.endswith("[0]")
    last = last_raw[:-3] if is_array_last else last_raw
    if isinstance(target, list):
        while len(target) <= 0:
            target.append({})
        if last:
            target[0][last] = value
        else:
            target[0] = value
    elif is_array_last:
        target[last] = [value]
    else:
        target[last] = value
    return target_dict


def default_value_for_schema(schema: dict, components: dict | None = None, param_name: str = ""):
    schema = resolve_schema_ref(schema or {}, components)
    name = str(param_name or "").lower()
    schema_type = get_schema_type(schema, components)
    if "email" in name:
        return "user@example.com"
    if any(token in name for token in ["phone", "tel", "mobile", "contact"]):
        return "010-1234-5678"
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        return [default_value_for_schema(schema.get("items", {}), components, param_name)]
    if schema_type == "object":
        return build_default_payload_from_schema(schema, components)
    return "test"


def default_value_for_query_param(param_name: str, schema: dict, components: dict | None = None):
    return default_value_for_schema(schema, components, param_name)


def build_default_payload_from_schema(schema: dict, components: dict | None = None) -> dict:
    schema = resolve_schema_ref(schema or {}, components)
    payload = {}
    for key, child_schema in (schema.get("properties") or {}).items():
        payload[key] = default_value_for_schema(child_schema, components, key)
    return payload


def find_readable_endpoints_for_post(post_path: str, validated_endpoints: dict) -> list[tuple[str, str]]:
    candidates = []
    normalized_post_path = post_path.rstrip("/")
    for ep_path, ep_methods in (validated_endpoints or {}).items():
        if "get" not in ep_methods:
            continue
        normalized_ep_path = ep_path.rstrip("/")
        if normalized_ep_path == normalized_post_path:
            candidates.append(("list", ep_path))
        elif normalized_ep_path.startswith(normalized_post_path) and "{" in ep_path:
            candidates.append(("single", ep_path))
    return candidates


def extract_id_from_response(resp_json, depth: int = 0):
    if depth > 3:
        return None
    if isinstance(resp_json, dict):
        for key in ["id", "uuid", "key", "no", "seq"]:
            if key in resp_json and resp_json[key] is not None:
                return resp_json[key]
        for value in resp_json.values():
            result = extract_id_from_response(value, depth + 1)
            if result is not None:
                return result
    return None


def extract_id_from_url(url: str):
    path_value = urllib.parse.urlparse(str(url or "")).path
    for segment in reversed(path_value.strip("/").split("/")):
        if re.fullmatch(r"\d+", segment or ""):
            return segment
    return None


def resource_tokens_from_path(path_value: str) -> set[str]:
    ignored = {"api", "v1", "v2", "admin", "admins", "seller", "sellers", "me", "auth", "login", "logout", "search", "check"}
    tokens = set()
    for segment in (path_value or "").split("/"):
        segment = segment.strip("{} ").lower()
        if not segment or segment in ignored or segment.startswith("{") or re.fullmatch(r"\d+", segment):
            continue
        tokens.add(segment)
        if segment.endswith("ies") and len(segment) > 3:
            tokens.add(segment[:-3] + "y")
        elif segment.endswith("s") and len(segment) > 1:
            tokens.add(segment[:-1])
    if "profile" in tokens:
        tokens.update({"user", "users", "member", "members", "account", "accounts"})
    return tokens


def admin_read_candidates_for_mutation(post_path: str, resource_id, admin_accounts: list[dict], fallback_base_url: str, fallback_endpoints: dict) -> list[tuple[dict, str, str]]:
    post_tokens = resource_tokens_from_path(post_path)
    candidates = []
    for admin_account in admin_accounts:
        admin_base = admin_account.get("base_url", fallback_base_url).rstrip("/")
        admin_endpoints = admin_account.get("validated_endpoints", fallback_endpoints)
        for get_path, get_methods in (admin_endpoints or {}).items():
            if "get" not in get_methods or "admin" not in get_path.lower():
                continue
            get_tokens = resource_tokens_from_path(get_path)
            if post_tokens and not (post_tokens & get_tokens):
                continue
            if "{" in get_path:
                if not resource_id:
                    continue
                resolved_path = re.sub(r"\{[^}]+\}", str(resource_id), get_path)
            else:
                resolved_path = get_path
            candidates.append((admin_account, get_path, f"{admin_base}/{resolved_path.lstrip('/')}"))

    deduped = []
    seen = set()
    for item in candidates:
        key = (item[0].get("role"), item[2])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped[:20]
