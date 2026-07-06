"""Detect information disclosure in HTTP error responses (6-1)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LeakHit:
    rule_id: str
    severity: str
    category: str
    marker: str
    hint: str
    confidence: str = "high"


_RE_FLAGS = re.IGNORECASE | re.MULTILINE

_DB_PATTERNS: list[tuple[str, str, str]] = [
    (r"sqlsyntaxerrorexception|sqlexception|sqlstate\[", "sql_exception", "SQL exception text"),
    (r"mysql|mariadb|postgresql|sqlite|oracle|sql server|jdbc:", "db_vendor", "Database vendor hint"),
    (r"ora-\d{5}|pg::|syntax error at or near", "db_syntax", "DB syntax error"),
    (r"duplicate entry|foreign key constraint|violates .* constraint", "db_constraint", "DB constraint detail"),
]

_STACK_PATTERNS: list[tuple[str, str, str]] = [
    (r"\bat\s+[\w.$]+\([\w./\\:]+\)", "java_stack", "Java stack frame"),
    (r"caused by:\s*\w", "java_caused", "Java Caused by chain"),
    (r"traceback \(most recent call last\)", "python_trace", "Python traceback"),
    (r'file "(/|\\)[^"]+", line \d+', "python_file", "Python source path"),
    (r"fatal error:|parse error:|warning:.* in /", "php_error", "PHP error with path"),
    (r"at microsoft\.|at system\.|system\.\w+exception", "dotnet_stack", ".NET exception"),
    (r"nested exception is", "nested_exception", "Nested exception chain"),
    (
        r"server error in '/' application|"
        r"microsoft vbscript runtime error|"
        r"microsoft ole db provider for|"
        r"compilation error|"
        r"an unhandled exception occurred while processing the request",
        "aspnet_debug",
        "ASP.NET / classic ASP debug page",
    ),
    (
        r"django version:|you're seeing this error because you have debug = true|"
        r"disallowedhost at |exception type:.*exception value:",
        "django_debug",
        "Django debug error page",
    ),
    (r"werkzeug debugger|traceback \(most recent call last\).*flask", "flask_debug", "Flask/Werkzeug debug page"),
    (
        r"at object\.<anonymous>|internal/modules/cjs/loader\.js|unhandledpromiserejection|"
        r"throw err;\s*\^",
        "node_stack",
        "Node.js/Express stack trace",
    ),
    (
        r"actioncontroller::routingerror|app/controllers/.*\.rb:\d+|"
        r"activerecord::\w*error",
        "rails_stack",
        "Ruby on Rails stack trace",
    ),
    (r"weblogic\.\w+\.\w+exception|weblogic\.servlet", "weblogic_stack", "WebLogic exception leak"),
    (r"jeus\.\w+\.\w+exception|tmax jeus", "jeus_stack", "Jeus exception leak"),
]

_PATH_PATTERNS: list[tuple[str, str, str]] = [
    (r"/users/[\w.-]+/|/home/[\w.-]+/", "unix_home_path", "Unix home path in response"),
    (r"[a-z]:\\[\w\\.-]+", "windows_path", "Windows path in response"),
    (r"/var/www/|/app/|/opt/|/usr/local/", "server_path", "Server filesystem path"),
    (r"\.java:\d+|\.py:\d+|\.php:\d+", "source_line", "Source file:line reference"),
]

_FRAMEWORK_PATTERNS: list[tuple[str, str, str]] = [
    (r"whitelabel error page", "spring_whitelabel", "Spring Whitelabel error page"),
    (r"org\.springframework\.|springframework/web", "spring_framework", "Spring framework leak"),
    (r"org\.hibernate\.|hibernate exception", "hibernate", "Hibernate leak"),
    (r"tomcat\.|apache tomcat|error report", "tomcat", "Tomcat default error"),
    (r"nginx/\d|apache/\d", "web_server_banner", "Web server version in body"),
    (
        r"iis (detailed error|10\.0 detailed error)|the page cannot be displayed|"
        r"http error 500\.19|http error 500\.0|internet information services",
        "iis_default",
        "IIS default error page",
    ),
    (r"webtob|tmaxsoft webtob", "webtob_default", "WebToB default error page"),
    (r"jeus error page|jeus web server", "jeus_default", "Jeus default error page"),
    (r"iplanet-web-server", "iplanet_banner", "iPlanet web server banner"),
]

_VERBOSE_PATTERNS: list[tuple[str, str, str]] = [
    (r"internal server error.*(exception|stack|trace)", "verbose_500", "Verbose 500 body"),
    (r"debug message|systemmessage|developer message", "verbose_field", "Verbose error field name"),
    (r"\"trace\"\s*:\s*\"", "json_trace_field", "JSON trace field with content"),
    (r"\"stack\"\s*:\s*\"", "json_stack_field", "JSON stack field with content"),
    (r"\"exception\"\s*:\s*\"", "json_exception_field", "JSON exception field with content"),
]

_ALL_RULES: list[tuple[str, str, list[tuple[str, str, str]]]] = [
    ("high", "database", _DB_PATTERNS),
    ("high", "stack_trace", _STACK_PATTERNS),
    ("medium", "path_disclosure", _PATH_PATTERNS),
    ("medium", "framework", _FRAMEWORK_PATTERNS),
    ("low", "verbose_error", _VERBOSE_PATTERNS),
]

# Categories whose patterns key off generic substrings / keyword co-occurrence
# rather than an unambiguous exception/stack signature. These can plausibly
# false-positive (e.g. a legitimate page mentioning "/opt/" or a long verbose
# 200 body), so hits here are downgraded to "review" instead of "high"
# confidence — a diagnostician should confirm before treating them as a fail.
_REVIEW_CATEGORIES = {"path_disclosure", "verbose_error"}


def _confidence_for_category(category: str) -> str:
    return "review" if category in _REVIEW_CATEGORIES else "high"


def _response_text(body: str | bytes | None, content_type: str | None) -> str:
    if body is None:
        return ""
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
    if "json" in ct or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass
    return text


def _match_patterns(
    text: str,
    patterns: list[tuple[str, str, str]],
    *,
    severity: str,
    category: str,
) -> list[LeakHit]:
    hits: list[LeakHit] = []
    lower = text.lower()
    confidence = _confidence_for_category(category)
    for pattern, rule_id, hint in patterns:
        if re.search(pattern, text, _RE_FLAGS) or re.search(pattern, lower, _RE_FLAGS):
            m = re.search(pattern, text, _RE_FLAGS) or re.search(pattern, lower, _RE_FLAGS)
            marker = m.group(0)[:120] if m else pattern
            hits.append(
                LeakHit(
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    marker=marker,
                    hint=hint,
                    confidence=confidence,
                )
            )
    return hits


def analyze_error_response(
    *,
    status_code: int,
    headers: dict[str, str] | None,
    body: str | bytes | None,
) -> list[LeakHit]:
    """Return leak hits when error status or body contains disclosure markers."""
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    content_type = hdrs.get("content-type", "")
    text = _response_text(body, content_type)
    if not text.strip():
        return []

    hits: list[LeakHit] = []
    seen: set[str] = set()
    for severity, category, patterns in _ALL_RULES:
        for hit in _match_patterns(text, patterns, severity=severity, category=category):
            if hit.rule_id in seen:
                continue
            seen.add(hit.rule_id)
            hits.append(hit)

    if status_code >= 500 and len(text) > 400 and any(
        k in text.lower() for k in ("exception", "stack", "trace", "sql", "caused by")
    ):
        key = "verbose_500_body"
        if key not in seen:
            hits.append(
                LeakHit(
                    rule_id=key,
                    severity="medium",
                    category="verbose_error",
                    marker=text[:80].replace("\n", " "),
                    hint="Large 5xx body with exception-like content",
                    confidence="review",
                )
            )
    return hits


def remediation_hint(rule_id: str) -> str:
    hints = {
        "sql_exception": "Map DB errors to generic client messages; log details server-side only.",
        "java_stack": "Disable stack traces in production error responses.",
        "python_trace": "Set DEBUG=False / disable traceback in API error handlers.",
        "spring_whitelabel": "Use custom error pages; disable Whitelabel in production.",
        "json_trace_field": "Remove trace/stack fields from JSON error payloads (e.g. Spring error attributes).",
        "unix_home_path": "Strip filesystem paths from error messages.",
        "verbose_500_body": "Return minimal 5xx JSON/HTML without internal exception text.",
        "aspnet_debug": "Set customErrors mode=On in web.config; disable IIS/ASP.NET debug pages in production.",
        "django_debug": "Set DEBUG=False in Django settings and configure ALLOWED_HOSTS / custom 500 handler.",
        "flask_debug": "Disable Werkzeug debugger (debug=False) in production Flask/WSGI config.",
        "node_stack": "Add a generic error-handling middleware; never send err.stack to the client.",
        "rails_stack": "Set config.consider_all_requests_local = false and config.action_dispatch.show_exceptions = false.",
        "weblogic_stack": "Configure WebLogic error-page mapping (web.xml) for all HTTP codes; disable verbose faults.",
        "jeus_stack": "Set print-error-to-browser=false in WEBMain.xml and configure Jeus error documents.",
        "iis_default": "Configure IIS custom error pages (Error Pages panel) for 400/401/403/404/405/500.",
        "webtob_default": "Configure ErrorDocument mapping in WebToB's http.m for all error codes.",
        "jeus_default": "Configure Jeus admin console error-document settings per node/engine.",
        "iplanet_banner": "Configure obj.conf Error fn=\"send-error\" for each error reason with a custom page.",
    }
    return hints.get(rule_id, "Return generic error pages without internal implementation details.")