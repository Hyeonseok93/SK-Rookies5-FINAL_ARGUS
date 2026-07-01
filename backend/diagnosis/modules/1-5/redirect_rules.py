"""Guideline 1-5 — open redirect, CORS, crossdomain.xml heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

REDIRECT_PARAM_NAMES: tuple[str, ...] = (
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirectUrl",
    "return",
    "returnUrl",
    "return_url",
    "returl",
    "retUrl",
    "next",
    "continue",
    "url",
    "target",
    "dest",
    "destination",
    "goto",
    "go",
    "forward",
    "fwd",
    "to",
    "out",
    "redir",
    "link",
    "callback",
    "continueTo",
)

SKIP_FUZZ_PARAM_NAMES = frozenset(
    {
        "page",
        "size",
        "limit",
        "offset",
        "sort",
        "order",
        "direction",
        "q",
        "keyword",
        "search",
        "id",
        "ids",
        "returnDate",
        "returnTime",
        "departureDate",
        "targetId",
        "targetType",
    }
)

REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

CROSSDOMAIN_PERMISSIVE_RE = re.compile(
    r'<allow-access-from\s+domain\s*=\s*["\'](\*|[^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass
class ScanRules:
    strict_baseline: bool = True


def sink_token_url(sink_base: str, run_id: str, probe_id: str) -> str:
    base = sink_base.rstrip("/")
    return f"{base}/r/{run_id}/{probe_id}"


def sink_host(sink_base: str) -> str:
    return (urlparse(sink_base).hostname or "").lower()


def location_points_to_sink(location: str | None, sink_base: str) -> bool:
    if not location:
        return False
    loc = location.strip()
    host = sink_host(sink_base)
    if not host:
        return False
    if loc.startswith("//"):
        part = loc[2:].split("/")[0].split(":")[0].lower()
        return part == host
    parsed = urlparse(loc)
    if (parsed.hostname or "").lower() == host:
        return True
    return host in loc.lower()


def is_external_open_redirect(
    status: int | None,
    location: str | None,
    *,
    sink_base: str,
    baseline_location: str | None,
) -> bool:
    if status not in REDIRECT_STATUS_CODES:
        return False
    if not location_points_to_sink(location, sink_base):
        return False
    if baseline_location and location_points_to_sink(baseline_location, sink_base):
        return False
    if baseline_location and baseline_location.strip() == (location or "").strip():
        return False
    return True


def should_fuzz_param(name: str, *, param_in: str) -> bool:
    if param_in not in ("query", "body", "form"):
        return False
    if name.lower() in SKIP_FUZZ_PARAM_NAMES:
        return False
    return True


def analyze_cors_headers(
    headers: dict[str, str],
    *,
    probe_origin: str,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "").lower()
    if not acao:
        return issues
    if acao.strip() == "*":
        if acac == "true":
            issues.append(
                {
                    "reason": "cors_wildcard_with_credentials",
                    "severity": "high",
                    "acao": acao,
                    "acac": acac,
                }
            )
        else:
            issues.append(
                {
                    "reason": "cors_wildcard_origin",
                    "severity": "medium",
                    "acao": acao,
                    "acac": acac,
                }
            )
        return issues
    if acao.strip() == probe_origin.strip() and acac == "true":
        issues.append(
            {
                "reason": "cors_reflect_origin_with_credentials",
                "severity": "high",
                "acao": acao,
                "acac": acac,
                "probe_origin": probe_origin,
            }
        )
    elif acao.strip() == probe_origin.strip():
        issues.append(
            {
                "reason": "cors_reflect_origin",
                "severity": "medium",
                "acao": acao,
                "acac": acac,
                "probe_origin": probe_origin,
            }
        )
    return issues


def analyze_crossdomain_xml(body: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for match in CROSSDOMAIN_PERMISSIVE_RE.finditer(body or ""):
        domain = match.group(1)
        if domain == "*":
            issues.append({"reason": "crossdomain_wildcard", "severity": "medium", "domain": domain})
        else:
            issues.append(
                {
                    "reason": "crossdomain_allow_from",
                    "severity": "info",
                    "domain": domain,
                }
            )
    return issues
