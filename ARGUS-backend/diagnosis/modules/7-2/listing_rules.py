"""Detect directory listing in HTTP response bodies (7-2)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

# Apache / nginx / IIS / generic
LISTING_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("apache_index", re.compile(r"index of /", re.IGNORECASE), "medium"),
    ("nginx_autoindex_title", re.compile(r"<title>\s*index of\b", re.IGNORECASE), "medium"),
    ("directory_listing_for", re.compile(r"directory listing for", re.IGNORECASE), "medium"),
    ("directory_of", re.compile(r"directory of\b", re.IGNORECASE), "medium"),
    ("parent_directory", re.compile(r"parent directory", re.IGNORECASE), "medium"),
    ("iis_directory_listing", re.compile(r"- directory listing\b", re.IGNORECASE), "medium"),
    ("tomcat_listings", re.compile(r"directory listing\b.*<hr>", re.IGNORECASE | re.DOTALL), "medium"),
    ("caddy_file_server", re.compile(r"caddy.*file.?server|file server\b", re.IGNORECASE), "low"),
    ("lighttpd_listing", re.compile(r"lighttpd.*directory listing", re.IGNORECASE), "medium"),
)

FILE_EXT_IN_HREF = re.compile(
    r'href="[^"]+\.(?:html?|php|asp|aspx|jsp|js|css|png|jpe?g|gif|svg|webp|ico|pdf|zip|tar|gz|sql|env|xml|json|txt|bak|old|log|conf|yaml|yml|md)(?:\?[^"]*)?"',
    re.IGNORECASE,
)


@dataclass
class ListingIssue:
    reason: str
    severity: str
    matched_patterns: list[str]
    link_count: int
    listing_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "severity": self.severity,
            "matched_patterns": self.matched_patterns,
            "link_count": self.link_count,
            "listing_type": self.listing_type,
        }


def _body_fingerprint(body: str) -> str:
    normalized = re.sub(r"\s+", " ", body.strip().lower())[:8000]
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _count_file_links(body: str) -> int:
    return len(FILE_EXT_IN_HREF.findall(body))


def _is_spa_duplicate(body: str, baseline_body: str | None, *, baseline_fp: str | None) -> bool:
    if not baseline_body:
        return False
    if baseline_fp and _body_fingerprint(body) == baseline_fp:
        return True
    # Same length ± small delta and high overlap → likely same SPA shell
    if abs(len(body) - len(baseline_body)) < 64:
        if body.strip() == baseline_body.strip():
            return True
    return False


def classify_listing_response(
    body: str,
    *,
    content_type: str = "",
    baseline_body: str | None = None,
    baseline_fp: str | None = None,
    http_status: int | None = None,
) -> ListingIssue | None:
    """
    Return issue if body looks like webserver directory listing.

    Skips SPA fallback when body matches base URL baseline.
    """
    if http_status is not None and http_status not in (200, 203, 206):
        return None

    text = body or ""
    if len(text) < 80:
        return None

    ct = (content_type or "").lower()
    if ct and not any(t in ct for t in ("text/html", "text/plain", "application/xhtml")):
        if "json" in ct or "javascript" in ct:
            return None

    if _is_spa_duplicate(text, baseline_body, baseline_fp=baseline_fp):
        return None

    matched: list[str] = []
    severity = "low"
    listing_type = "unknown"

    for name, pattern, sev in LISTING_PATTERNS:
        if pattern.search(text):
            matched.append(name)
            if sev == "medium":
                severity = "medium"
            if "nginx" in name:
                listing_type = "nginx_autoindex"
            elif "apache" in name:
                listing_type = "apache_indexes"
            elif "iis" in name:
                listing_type = "iis"
            elif listing_type == "unknown":
                listing_type = name

    link_count = _count_file_links(text)
    has_parent = "../" in text or "parent directory" in text.lower()

    if not matched and link_count >= 4 and has_parent:
        matched.append("multi_file_link_heuristic")
        listing_type = "heuristic_links"
        severity = "low"

    if not matched:
        return None

    reason = "directory_listing_" + (matched[0] if len(matched) == 1 else "multiple")
    return ListingIssue(
        reason=reason,
        severity=severity,
        matched_patterns=matched,
        link_count=link_count,
        listing_type=listing_type,
    )


def remediation_hint(listing_type: str) -> str:
    hints = {
        "nginx_autoindex": "nginx: set autoindex off; in server/location block",
        "apache_indexes": "Apache: Options -Indexes or IndexOptions -Indexes",
        "iis": "IIS: disable Directory Browsing for the site/virtual directory",
        "tomcat_listings": "Tomcat: listings=\"false\" on DefaultServlet / web.xml",
    }
    return hints.get(listing_type, "Disable directory listing (Indexes/autoindex) per KISA 7-2")
