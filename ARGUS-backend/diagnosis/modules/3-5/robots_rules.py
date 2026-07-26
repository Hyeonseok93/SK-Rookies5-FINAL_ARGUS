"""Parse robots.txt and HTML/header robots directives for 3-5 (inventory mode)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.robotparser import RobotFileParser

_META_ROBOTS_RE = re.compile(
    r'<meta\s+[^>]*name\s*=\s*["\']?(?:robots|googlebot|bingbot)["\']?\s+[^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_CONTENT_FIRST_RE = re.compile(
    r'<meta\s+[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']?(?:robots|googlebot|bingbot)["\']?',
    re.IGNORECASE,
)


@dataclass
class RobotsDirective:
    index: bool = True
    follow: bool = True
    raw: str = ""

    @property
    def has_noindex(self) -> bool:
        return not self.index

    @property
    def has_nofollow(self) -> bool:
        return not self.follow


@dataclass
class RobotsTxtInfo:
    status: int | None
    present: bool
    disallow_paths: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    body_excerpt: str = ""


@dataclass
class PageRobotsSignals:
    url: str
    http_status: int | None
    content_type: str
    x_robots_tag: str | None
    meta_robots: str | None
    header: RobotsDirective | None
    meta: RobotsDirective | None
    has_noindex: bool
    has_nofollow: bool
    has_any_directive: bool


def _tokenize_directive(raw: str) -> RobotsDirective:
    text = raw.strip().lower()
    if not text:
        return RobotsDirective()
    if text in ("none", "noindex, nofollow", "nofollow, noindex"):
        return RobotsDirective(index=False, follow=False, raw=raw)
    tokens = {t.strip() for t in text.replace(";", ",").split(",") if t.strip()}
    index = "noindex" not in tokens
    follow = "nofollow" not in tokens
    if "none" in tokens:
        index = False
        follow = False
    return RobotsDirective(index=index, follow=follow, raw=raw)


def parse_robots_directive(raw: str) -> RobotsDirective:
    return _tokenize_directive(raw)


def parse_meta_robots(html: str) -> RobotsDirective | None:
    if not html:
        return None
    head = html[:120_000]
    for pattern in (_META_ROBOTS_RE, _META_CONTENT_FIRST_RE):
        match = pattern.search(head)
        if match:
            return parse_robots_directive(match.group(1))
    return None


def parse_x_robots_tag(header_value: str) -> RobotsDirective | None:
    value = (header_value or "").strip()
    if not value:
        return None
    return parse_robots_directive(value)


def parse_robots_txt(body: str, *, status: int | None = None) -> RobotsTxtInfo:
    text = body or ""
    info = RobotsTxtInfo(status=status, present=status == 200 and bool(text.strip()))
    if status != 200:
        return info

    agents: list[str] = []
    disallow: list[str] = []
    allow: list[str] = []

    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "user-agent" and val and val not in agents:
            agents.append(val)
        elif key == "disallow" and val:
            disallow.append(val)
        elif key == "allow" and val:
            allow.append(val)
        elif key == "sitemap" and val:
            info.sitemaps.append(val)

    info.disallow_paths = sorted(set(disallow))
    info.allow_paths = sorted(set(allow))
    info.user_agents = agents
    info.body_excerpt = text[:800]
    return info


def is_html_response(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if "html" in ct:
        return True
    sample = (body or "")[:300].lstrip().lower()
    return sample.startswith("<!doctype html") or sample.startswith("<html")


def extract_page_robots_signals(
    url: str,
    *,
    http_status: int | None,
    content_type: str,
    body: str,
    x_robots: str,
) -> PageRobotsSignals | None:
    if http_status is not None and http_status >= 400:
        return None

    header_dir = parse_x_robots_tag(x_robots)
    meta_dir = parse_meta_robots(body) if is_html_response(content_type, body) else None

    has_noindex = bool(
        (header_dir and header_dir.has_noindex) or (meta_dir and meta_dir.has_noindex)
    )
    has_nofollow = bool(
        (header_dir and header_dir.has_nofollow) or (meta_dir and meta_dir.has_nofollow)
    )
    has_any = bool(header_dir or meta_dir)

    if not has_any:
        return PageRobotsSignals(
            url=url,
            http_status=http_status,
            content_type=content_type,
            x_robots_tag=x_robots or None,
            meta_robots=None,
            header=header_dir,
            meta=meta_dir,
            has_noindex=False,
            has_nofollow=False,
            has_any_directive=False,
        )

    return PageRobotsSignals(
        url=url,
        http_status=http_status,
        content_type=content_type,
        x_robots_tag=x_robots or None,
        meta_robots=meta_dir.raw if meta_dir else None,
        header=header_dir,
        meta=meta_dir,
        has_noindex=has_noindex,
        has_nofollow=has_nofollow,
        has_any_directive=True,
    )
