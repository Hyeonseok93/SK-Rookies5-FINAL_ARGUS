"""Classify response headers for guideline 7-3."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --- Fixed disclosure headers (KISA + OWASP WSTG CONFIG-02 + ZAP passive) ---
DISCLOSURE_HEADERS: frozenset[str] = frozenset(
    {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-aspnet",
        "x-runtime",
        "x-generator",
        "x-version",
        "x-powered-cms",
        "x-served-by",
        "x-sourcefiles",
        "x-environment",
        "x-backend-server",
        "x-forwarded-server",
        "x-application-context",
        "x-server-powered-by",
        "x-server-name",
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
        "x-mod-pagespeed",
        "x-jenkins",
        "x-framework",
        "x-technology",
        "x-cf-powered-by",
        "lws-info",
    }
)

# Strict: header *name* hints (catches X-Custom-Version etc.)
DISCLOSURE_NAME_PATTERN = re.compile(
    r"(?:^server$|"
    r"^x-(?:powered|aspnet|generator|runtime|version|served|backend|forwarded|"
    r"application-context|drupal|mod-pagespeed|jenkins|framework|technology|"
    r"environment|sourcefiles|server)|"
    r"(?:version|powered|aspnet|backend|generator|runtime|technology|framework|environment))",
    re.IGNORECASE,
)

VERSION_PATTERN = re.compile(
    r"(?:\b|/|v)"
    r"\d+\.\d+(?:\.\d+)?(?:\.\d+)?(?:\.\d+)?"
    r"(?:\b|$|[^\d])",
    re.IGNORECASE,
)
VERSION_ONLY_PATTERN = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:\.\d+)?(?:\.\d+)?$")
# PHP/8, Node/20, ASP.NET 4.x style without minor.patch
SLASH_VERSION_PATTERN = re.compile(r"/\d+(?:\.\d+)?(?:\.\d+)?", re.IGNORECASE)

STACK_PRODUCTS = (
    "apache",
    "nginx",
    "microsoft-iis",
    "iis",
    "tomcat",
    "jetty",
    "undertow",
    "gunicorn",
    "uvicorn",
    "hypercorn",
    "waitress",
    "express",
    "fastify",
    "koa",
    "nestjs",
    "php",
    "asp.net",
    "aspnet",
    "weblogic",
    "jboss",
    "wildfly",
    "webtob",
    "openresty",
    "caddy",
    "spring",
    "springboot",
    "django",
    "flask",
    "rails",
    "laravel",
    "sinatra",
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "cloudflare",
    "kestrel",
    "node",
    "node.js",
    "okhttp",
    "werkzeug",
    "golang",
    "cowboy",
    "lighttpd",
    "litespeed",
    "resin",
    "glassfish",
    "payara",
    "unicorn",
    "puma",
    "passenger",
    "phusion",
    "next.js",
    "nuxt",
    "vite",
    "webpack",
    "vercel",
    "netlify",
    "traefik",
    "haproxy",
    "envoy",
    "varnish",
    "squid",
)

ENV_DISCLOSURE_VALUES = frozenset(
    {
        "staging",
        "stage",
        "development",
        "dev",
        "test",
        "testing",
        "production",
        "prod",
        "qa",
        "uat",
        "sandbox",
        "local",
        "preview",
    }
)

BENIGN_VALUES = frozenset(
    {
        "",
        " ",
        "webserver",
        "unknown",
        "hidden",
        "none",
        "null",
        "-",
        "n/a",
        "na",
        "default",
        "secure",
    }
)

# CDN / cache — only when include_cdn_headers=True (strict+CDN)
CDN_HEADERS = frozenset({"via", "x-cache", "x-cache-hits", "cf-ray", "x-served-from"})


@dataclass
class ScanRules:
    """7-3 scan strictness (default: strict)."""

    strict: bool = True
    include_cdn_headers: bool = False
    extra_headers: frozenset[str] = field(default_factory=frozenset)


@dataclass
class HeaderIssue:
    header: str
    value: str
    severity: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header,
            "value": self.value,
            "severity": self.severity,
            "reason": self.reason,
        }


def _disclosure_header_set(rules: ScanRules) -> frozenset[str]:
    base = set(DISCLOSURE_HEADERS) | {h.lower() for h in rules.extra_headers}
    if rules.include_cdn_headers:
        base |= CDN_HEADERS
    return frozenset(base)


def _is_disclosure_header(name: str, rules: ScanRules) -> bool:
    key = name.lower().strip()
    if key in _disclosure_header_set(rules):
        return True
    if rules.strict and DISCLOSURE_NAME_PATTERN.search(key):
        return True
    return False


def _has_version(value: str) -> bool:
    val = value.strip()
    if VERSION_ONLY_PATTERN.match(val):
        return True
    if SLASH_VERSION_PATTERN.search(val):
        return True
    return bool(VERSION_PATTERN.search(val))


def _has_stack_product(value: str) -> bool:
    lower = value.lower()
    return any(p in lower for p in STACK_PRODUCTS)


def _is_environment_disclosure(key: str, value: str) -> bool:
    if key not in {"x-environment", "x-env", "x-stage", "x-deployment-environment"}:
        return False
    return value.strip().lower() in ENV_DISCLOSURE_VALUES


def _severity_for(
    *,
    rules: ScanRules,
    reason: str,
) -> str:
    if reason == "version_disclosed":
        return "medium"
    if rules.strict:
        # Strict: any stack/product/env hint is at least medium
        return "medium"
    return "low"


def classify_header(
    name: str,
    value: str,
    *,
    rules: ScanRules | None = None,
) -> HeaderIssue | None:
    """
    Return issue if header discloses server/stack info.

    strict=True (default):
    - fixed list + name-pattern heuristic headers
    - product-only / env name / generic stack → medium (not low)
    """
    rules = rules or ScanRules()
    key = name.lower().strip()
    if not _is_disclosure_header(key, rules):
        return None

    val = (value or "").strip()
    if val.lower() in BENIGN_VALUES:
        return None

    if _has_version(val):
        return HeaderIssue(
            header=key,
            value=val,
            severity="medium",
            reason="version_disclosed",
        )

    if _is_environment_disclosure(key, val):
        return HeaderIssue(
            header=key,
            value=val,
            severity=_severity_for(rules=rules, reason="environment_disclosed"),
            reason="environment_disclosed",
        )

    if _has_stack_product(val):
        return HeaderIssue(
            header=key,
            value=val,
            severity=_severity_for(rules=rules, reason="product_name_disclosed"),
            reason="product_name_disclosed",
        )

    return HeaderIssue(
        header=key,
        value=val,
        severity=_severity_for(rules=rules, reason="stack_or_server_disclosed"),
        reason="stack_or_server_disclosed",
    )


def scan_response_headers(
    headers: dict[str, str],
    *,
    rules: ScanRules | None = None,
) -> list[HeaderIssue]:
    rules = rules or ScanRules()
    issues: list[HeaderIssue] = []
    seen: set[str] = set()
    for name, value in headers.items():
        issue = classify_header(name, value, rules=rules)
        if issue is None:
            continue
        dedupe = f"{issue.header}:{issue.value}"
        if dedupe in seen:
            continue
        seen.add(dedupe)
        issues.append(issue)
    return issues


def scan_rules_from_config(raw: dict[str, Any]) -> ScanRules:
    cfg = raw.get("diagnosis_7_3") or raw.get("scan_7_3") or {}
    extra = cfg.get("extra_headers") or []
    return ScanRules(
        strict=bool(cfg.get("strict", True)),
        include_cdn_headers=bool(cfg.get("include_cdn_headers", False)),
        extra_headers=frozenset(str(h).lower() for h in extra if h),
    )
