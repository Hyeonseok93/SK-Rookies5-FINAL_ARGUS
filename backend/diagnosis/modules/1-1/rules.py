"""Detection rules for ARGUS 1-1 XSS/CSRF findings."""

from __future__ import annotations

import html
import json
import re
import urllib.parse
import difflib


def get_payload_reflection(payload: str, response_body: str, baseline_body: str | None = None) -> str | None:
    if not payload or not response_body:
        return None

    active_text = response_body
    if baseline_body:
        try:
            diff = difflib.ndiff(baseline_body.splitlines(keepends=True), response_body.splitlines(keepends=True))
            added_lines = [line[2:] for line in diff if line.startswith("+ ")]
            active_text = "".join(added_lines)
            if not active_text.strip():
                return None
        except Exception:
            active_text = response_body

    payload_variants = {
        payload,
        html.escape(payload),
        html.escape(payload, quote=False),
        urllib.parse.quote(payload),
        urllib.parse.quote_plus(payload),
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E"),
    }
    body_variants = {
        active_text,
        html.unescape(active_text),
        urllib.parse.unquote(active_text),
        urllib.parse.unquote_plus(active_text),
    }

    for body in body_variants:
        body_lower = body.lower()
        for variant in payload_variants:
            if variant and variant.lower() in body_lower:
                return variant
    return None


def is_payload_reflected(payload: str, response_body: str, baseline_body: str | None = None) -> bool:
    return get_payload_reflection(payload, response_body, baseline_body) is not None


def detect_xss_reflection_context(payload: str, response_body: str) -> str | None:
    if not payload or not response_body:
        return "unknown"
    body = html.unescape(urllib.parse.unquote_plus(response_body))
    payload_re = re.escape(payload)
    if re.search(r"<[^>]+\s[\w:-]+\s*=\s*(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
        return "HTML attribute"
    if re.search(r">\s*" + payload_re + r"\s*<", body, re.IGNORECASE):
        return "HTML body"
    if re.search(r"(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
        return "JSON/String value"
    return "encoded/reflected"


def classify_xss_response(
    payload: str,
    response_body: str,
    content_type: str,
    method: str = "GET",
    is_mutation: bool = False,
    response_headers: dict | None = None,
    baseline_body: str | None = None,
) -> dict | None:
    response_headers = response_headers or {}
    content_type = (content_type or "").lower()
    reflected_variant = get_payload_reflection(payload, response_body, baseline_body)

    body_lower = (response_body or "").lower()
    dom_sink_patterns = [
        "document.write",
        "document.writeln",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "eval(",
        "settimeout(",
        "setinterval(",
        "window.location",
        "document.location",
        "location.href",
        "appendchild",
        "insertbefore",
    ]
    source_indicators = ["location", "search", "document.cookie", "document.location", "url", "query", "param", "input"]
    executable_markers = ["<script", "</script>", "onerror=", "onload=", "onclick=", "javascript:", "<svg", "<img", "<iframe"]
    has_dom_sink = any(sink in body_lower for sink in dom_sink_patterns)
    has_source = any(src in body_lower for src in source_indicators)
    has_payload_in_body = reflected_variant is not None
    has_executable_marker = any(marker in body_lower for marker in executable_markers)
    if has_dom_sink and has_source and (has_payload_in_body or has_executable_marker):
        return {
            "kind": "dom_suspect",
            "risk": "Informational",
            "confidence": "Low",
            "custom_type": "DOM_XSS_SUSPECT",
            "alert": "DOM XSS Suspect",
            "description": "DOM sink and user-controlled source patterns were found; dynamic browser verification is recommended.",
            "evidence": "Response body contains DOM sink/source patterns.",
            "playwright_action": "manual browser execution recommended",
        }

    if not reflected_variant:
        return None

    nosniff = response_headers.get("X-Content-Type-Options") or response_headers.get("x-content-type-options") or ""
    is_html_context = "html" in content_type
    is_json_context = "json" in content_type
    if "json" in content_type and "nosniff" in str(nosniff).lower():
        return None
    if not any(marker in payload.lower() for marker in executable_markers):
        return None
    if not (is_html_context or is_json_context):
        return None

    if is_html_context:
        risk = "Medium"
        confidence = "High"
        description = "Response reflected an executable XSS payload in an HTML context."
    else:
        risk = "Low"
        confidence = "Medium"
        description = "Response reflected an executable XSS payload in JSON; execution depends on unsafe client-side rendering."

    return {
        "kind": "reflected",
        "risk": risk,
        "confidence": confidence,
        "custom_type": "40012",
        "alert": "Reflected Cross-Site Scripting (Reflected XSS) Vulnerability",
        "description": description,
        "solution": "Escape untrusted output by context and reject executable markup in API input.",
        "reflection_context": detect_xss_reflection_context(payload, response_body),
        "reflected_variant": reflected_variant,
        "evidence": f"Response reflected payload variant '{reflected_variant}'.",
    }


def check_csrf_token_absence(response) -> bool:
    body = (getattr(response, "text", "") or "").lower()
    headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
    return not ("csrf" in body or "xsrf" in body or "x-csrf-token" in headers or "x-xsrf-token" in headers)


def assess_security_headers(response, is_https: bool = False) -> list[dict]:
    headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
    findings = []
    required = [
        ("x-content-type-options", "MIME_SNIFF_CUSTOM", "X-Content-Type-Options is missing"),
        ("x-frame-options", "X_FRAME_OPTIONS_CUSTOM", "X-Frame-Options is missing"),
        ("content-security-policy", "CSP_CUSTOM", "Content-Security-Policy is missing"),
        ("referrer-policy", "REFERRER_POLICY_CUSTOM", "Referrer-Policy is missing"),
        ("permissions-policy", "PERMISSIONS_POLICY_CUSTOM", "Permissions-Policy is missing"),
    ]
    for header, rule_id, message in required:
        if header not in headers:
            findings.append({"rule_id": rule_id, "message": message, "severity": "medium"})
    if is_https and "strict-transport-security" not in headers:
        findings.append({"rule_id": "HSTS_CUSTOM", "message": "Strict-Transport-Security is missing", "severity": "medium"})
    return findings


def find_json_keypaths_containing(value, payload: str, prefix: str = "") -> list[str]:
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(find_json_keypaths_containing(child, payload, f"{prefix}[{index}]"))
    elif isinstance(value, str) and payload in value:
        matches.append(prefix)
    return matches


def infer_reflected_response_params(response, payload: str) -> list[str]:
    try:
        return find_json_keypaths_containing(response.json(), payload)
    except Exception:
        return []


def reflected_near_resource_id(response_text: str, payload: str, resource_id) -> bool:
    if not is_payload_reflected(payload, response_text):
        return False
    if not resource_id:
        return True
    rid = str(resource_id)
    if rid not in response_text:
        return False
    idx = response_text.find(rid)
    return payload in response_text[max(0, idx - 250): idx + 750]


def safe_json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)
