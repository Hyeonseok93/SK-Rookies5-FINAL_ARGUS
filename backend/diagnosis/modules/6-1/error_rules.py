"""Detect information disclosure in HTTP error responses (6-1).

SK Shielders 6-1 checklist buckets:
  - dbms      : DBMS / SQL error disclosure
  - exception : stack traces, framework internals, path in exceptions
  - http      : server error messages, verbose HTTP pages, debug fields, ZAP disclosure
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

SK_DBMS = "dbms"
SK_EXCEPTION = "exception"
SK_HTTP = "http"

SK_LABELS: dict[str, str] = {
    SK_DBMS: "DBMS 오류",
    SK_EXCEPTION: "익셉션 오류",
    SK_HTTP: "HTTP/서버 오류",
}

_RE_FLAGS = re.IGNORECASE | re.MULTILINE

_TECHNICAL_MARKERS = (
    "exception",
    "stack",
    "trace",
    "sqlexception",
    "sqlstate",
    "caused by",
    "traceback",
    "at com.",
    "at org.",
    "at java.",
    "at sun.",
    ".java:",
    ".py:",
    "nested exception",
    "fatal error",
)


@dataclass(frozen=True)
class LeakHit:
    rule_id: str
    severity: str
    category: str
    sk_class: str
    marker: str
    hint: str


_DB_PATTERNS: list[tuple[str, str, str]] = [
    (r"sqlsyntaxerrorexception|sqlexception|sqlstate\[", "sql_exception", "SQL exception text"),
    (r"mysql|mariadb|postgresql|sqlite|oracle|sql server|jdbc:", "db_vendor", "Database vendor hint"),
    (r"ora-\d{5}|pg::|syntax error at or near", "db_syntax", "DB syntax error"),
    (r"duplicate entry|foreign key constraint|violates .* constraint", "db_constraint", "DB constraint detail"),
]

_JAVA_STACK_PATTERNS: list[tuple[str, str, str]] = [
    (r"\bat\s+[\w.$]+\([\w./\\:]+\)", "java_stack", "Java stack frame"),
    (r"caused by:\s*\w", "java_caused", "Java Caused by chain"),
    (r"nested exception is", "nested_exception", "Nested exception chain"),
]

_PY_DOTNET_PATTERNS: list[tuple[str, str, str]] = [
    (r"traceback \(most recent call last\)", "python_trace", "Python traceback"),
    (r'file "(/|\\)[^"]+", line \d+', "python_file", "Python source path"),
    (r"at microsoft\.|at system\.|system\.\w+exception", "dotnet_stack", ".NET exception"),
]

_PHP_PATTERNS: list[tuple[str, str, str]] = [
    (r"fatal error:.* in /", "php_fatal", "PHP fatal error with path"),
    (r"parse error:.* in /", "php_parse", "PHP parse error with path"),
    (r"warning:.* in /[^\s]+\.php", "php_warning", "PHP warning with path"),
]

_PATH_PATTERNS: list[tuple[str, str, str]] = [
    (r"/users/[\w.-]+/|/home/[\w.-]+/", "unix_home_path", "Unix home path in response"),
    (r"[a-z]:\\[\w\\.-]+", "windows_path", "Windows path in response"),
    (r"/var/www/|/app/|/opt/|/usr/local/", "server_path", "Server filesystem path"),
    (r"\.java:\d+|\.py:\d+|\.php:\d+", "source_line", "Source file:line reference"),
]

_FRAMEWORK_PATTERNS: list[tuple[str, str, str]] = [
    (r"whitelabel error page", "spring_whitelabel", "Spring Whitelabel error page"),
    (r"org\.hibernate\.|hibernate exception", "hibernate", "Hibernate leak"),
    (r"tomcat\.|apache tomcat|error report", "tomcat", "Tomcat default error"),
]

_SPRING_STRICT_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"org\.springframework\.[\w.$]+exception|springframework/web.*exception",
        "spring_framework",
        "Spring framework exception leak",
    ),
]

_HTTP_PATTERNS: list[tuple[str, str, str]] = [
    (r"internal server error.*(exception|stack|trace)", "verbose_500", "Verbose 5xx HTML/text body"),
    (r"debug message|developer message", "verbose_field", "Debug/developer error field name"),
    (r'"systemMessage"\s*:\s*"[^"]{1,}"', "json_system_message", "JSON systemMessage field (server error text)"),
    (r'"trace"\s*:\s*"[^"]{8,}"', "json_trace_field", "JSON trace field with content"),
    (r'"stack"\s*:\s*"[^"]{8,}"', "json_stack_field", "JSON stack field with content"),
    (r'"exception"\s*:\s*"[^"]{8,}"', "json_exception_field", "JSON exception field with content"),
    (r"nginx/\d|apache/\d", "web_server_banner", "Web server version in body"),
]

_CATEGORY_SK: dict[str, str] = {
    "database": SK_DBMS,
    "stack_trace": SK_EXCEPTION,
    "path_disclosure": SK_EXCEPTION,
    "framework": SK_EXCEPTION,
    "verbose_error": SK_HTTP,
    "zap_error_disclosure": SK_HTTP,
}

_RULE_SK: dict[str, str] = {
    "6-1-zap-90022": SK_HTTP,
    "6-1-zap-10023": SK_HTTP,
    "web_server_banner": SK_HTTP,
    "tomcat": SK_HTTP,
    "verbose_500": SK_HTTP,
    "verbose_500_body": SK_HTTP,
    "verbose_field": SK_HTTP,
    "json_system_message": SK_HTTP,
    "server_error_message": SK_HTTP,
    "json_error_field": SK_HTTP,
    "api_error_envelope": SK_HTTP,
}


def classify_sk(*, category: str, rule_id: str) -> str:
    if rule_id in _RULE_SK:
        return _RULE_SK[rule_id]
    return _CATEGORY_SK.get(category, SK_HTTP)


def _response_text(body: str | bytes | None, content_type: str | None) -> tuple[str, Any | None, bool]:
    if body is None:
        return "", None, False
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = repr(body[:4000])
    else:
        text = body
    if len(text) > 120_000:
        text = text[:120_000]
    ct = (content_type or "").lower()
    is_json = "json" in ct or text.lstrip().startswith(("{", "["))
    parsed: Any | None = None
    if is_json:
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, ensure_ascii=False), parsed, True
        except (json.JSONDecodeError, TypeError):
            pass
    return text, None, is_json and text.lstrip().startswith("{")


def _has_technical_leak(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in _TECHNICAL_MARKERS)


def _walk_strings(obj: Any) -> list[tuple[str, str]]:
    """Return (field_name, value) pairs from nested JSON structures."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str) and val.strip():
                out.append((str(key), val.strip()))
            elif isinstance(val, (dict, list)):
                out.extend(_walk_strings(val))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_strings(item))
    return out


def _detect_sk_api_error_json(parsed: Any, *, status_code: int) -> list[LeakHit]:
    """Flag server-side error text returned to the client (SK Shielders 6-1)."""
    if status_code < 400 or not isinstance(parsed, dict):
        return []

    hits: list[LeakHit] = []
    fields = _walk_strings(parsed)

    for key, value in fields:
        key_lower = key.lower()
        if key_lower == "systemmessage":
            hits.append(
                LeakHit(
                    rule_id="json_system_message",
                    severity="medium",
                    category="verbose_error",
                    sk_class=SK_HTTP,
                    marker=value[:120],
                    hint="systemMessage field exposes server error text to client",
                )
            )
            break

    msg = parsed.get("message")
    if isinstance(msg, str) and msg.strip():
        hits.append(
            LeakHit(
                rule_id="server_error_message",
                severity="medium",
                category="verbose_error",
                sk_class=SK_HTTP,
                marker=msg.strip()[:120],
                hint="Error response message field exposes server/application error text",
            )
        )

    err = parsed.get("error")
    if isinstance(err, str) and err.strip():
        hits.append(
            LeakHit(
                rule_id="json_error_field",
                severity="medium",
                category="verbose_error",
                sk_class=SK_HTTP,
                marker=err.strip()[:120],
                hint="Error string field in JSON error response",
            )
        )
    elif isinstance(err, dict):
        detail = err.get("message") or err.get("systemMessage") or err.get("detail")
        if isinstance(detail, str) and detail.strip():
            hits.append(
                LeakHit(
                    rule_id="json_error_field",
                    severity="medium",
                    category="verbose_error",
                    sk_class=SK_HTTP,
                    marker=detail.strip()[:120],
                    hint="Nested error object exposes server error text",
                )
            )

    if parsed.get("success") is False and not hits:
        hits.append(
            LeakHit(
                rule_id="api_error_envelope",
                severity="low",
                category="verbose_error",
                sk_class=SK_HTTP,
                marker="success:false",
                hint="API error envelope returned to client on failed request",
            )
        )

    return hits


def _match_patterns(
    text: str,
    patterns: list[tuple[str, str, str]],
    *,
    severity: str,
    category: str,
) -> list[LeakHit]:
    hits: list[LeakHit] = []
    lower = text.lower()
    for pattern, rule_id, hint in patterns:
        if not re.search(pattern, text, _RE_FLAGS) and not re.search(pattern, lower, _RE_FLAGS):
            continue
        m = re.search(pattern, text, _RE_FLAGS) or re.search(pattern, lower, _RE_FLAGS)
        marker = m.group(0)[:120] if m else pattern
        hits.append(
            LeakHit(
                rule_id=rule_id,
                severity=severity,
                category=category,
                sk_class=classify_sk(category=category, rule_id=rule_id),
                marker=marker,
                hint=hint,
            )
        )
    return hits


def _filter_hits(
    hits: list[LeakHit],
    *,
    status_code: int,
    is_json: bool,
) -> list[LeakHit]:
    out: list[LeakHit] = []
    seen: set[str] = set()
    for hit in hits:
        if hit.rule_id in seen:
            continue

        if hit.sk_class == SK_HTTP and status_code < 400:
            continue

        if is_json and hit.rule_id.startswith("php_"):
            continue

        seen.add(hit.rule_id)
        out.append(hit)
    return out


def analyze_error_response(
    *,
    status_code: int,
    headers: dict[str, str] | None,
    body: str | bytes | None,
) -> list[LeakHit]:
    """Return leak hits when error body contains disclosure markers."""
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    content_type = hdrs.get("content-type", "")
    text, parsed, is_json = _response_text(body, content_type)
    if not text.strip():
        return []

    hits: list[LeakHit] = []
    hits.extend(_match_patterns(text, _DB_PATTERNS, severity="high", category="database"))

    stack_patterns = list(_JAVA_STACK_PATTERNS)
    if not is_json:
        stack_patterns.extend(_PHP_PATTERNS)
    hits.extend(_match_patterns(text, stack_patterns, severity="high", category="stack_trace"))
    hits.extend(_match_patterns(text, _PY_DOTNET_PATTERNS, severity="high", category="stack_trace"))

    hits.extend(_match_patterns(text, _PATH_PATTERNS, severity="medium", category="path_disclosure"))
    hits.extend(_match_patterns(text, _FRAMEWORK_PATTERNS, severity="medium", category="framework"))
    if status_code >= 400 or _has_technical_leak(text):
        hits.extend(_match_patterns(text, _SPRING_STRICT_PATTERNS, severity="medium", category="framework"))

    if status_code >= 400:
        hits.extend(_match_patterns(text, _HTTP_PATTERNS, severity="low", category="verbose_error"))
        if parsed is not None:
            hits.extend(_detect_sk_api_error_json(parsed, status_code=status_code))

    if status_code >= 500 and len(text) > 400 and _has_technical_leak(text):
        hits.append(
            LeakHit(
                rule_id="verbose_500_body",
                severity="medium",
                category="verbose_error",
                sk_class=SK_HTTP,
                marker=text[:80].replace("\n", " "),
                hint="Large 5xx body with exception-like content",
            )
        )

    return _filter_hits(hits, status_code=status_code, is_json=is_json)


def remediation_hint(rule_id: str) -> str:
    hints = {
        "sql_exception": "Map DB errors to generic client messages; log details server-side only.",
        "java_stack": "Disable stack traces in production error responses.",
        "python_trace": "Set DEBUG=False / disable traceback in API error handlers.",
        "spring_whitelabel": "Use custom error pages; disable Whitelabel in production.",
        "json_trace_field": "Remove trace/stack fields from JSON error payloads (e.g. Spring error attributes).",
        "json_system_message": "Do not return systemMessage or internal error text to clients; log server-side only.",
        "server_error_message": "Return a generic user-facing message; keep server error details in logs only.",
        "json_error_field": "Remove detailed error fields from API error responses.",
        "api_error_envelope": "Use a unified generic error handler; avoid exposing server failure details in JSON.",
        "unix_home_path": "Strip filesystem paths from error messages.",
        "verbose_500_body": "Return minimal 5xx JSON/HTML without internal exception text.",
        "6-1-zap-90022": "Return generic 5xx responses without stack traces or debug text.",
        "6-1-zap-10023": "Disable debug error messages in production.",
    }
    return hints.get(rule_id, "Return generic error pages without internal implementation details.")
