"""Normalize URLs and auth for replay outside Docker."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse

DOCKER_HOST_ALIASES = frozenset({"host.docker.internal", "zap"})
LOCAL_PROBE_HOSTS = frozenset({"localhost", "127.0.0.1", *DOCKER_HOST_ALIASES})
FRONTEND_PORTS = frozenset({5173, 5174, 3000, 4173})


def _origin_dedupe_key(url: str) -> tuple[str, int]:
    parsed = urlparse(url.rstrip("/"))
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http") == "https" else 80
    return (parsed.scheme or "http", port)


def _canonical_host_rank(host: str) -> int:
    h = (host or "").lower()
    if h == "localhost":
        return 0
    if h == "127.0.0.1":
        return 1
    if h in DOCKER_HOST_ALIASES:
        return 2
    return 3


def dedupe_probe_bases(bases: list[str]) -> tuple[list[str], list[str]]:
    """
    Collapse localhost / 127.0.0.1 / host.docker.internal on the same port
    to one dashboard-facing base (prefer localhost for labels).
    """
    groups: dict[tuple[str, int], list[str]] = {}
    for raw in bases:
        url = raw.rstrip("/")
        if not url:
            continue
        groups.setdefault(_origin_dedupe_key(url), []).append(url)

    kept: list[str] = []
    dropped: list[str] = []
    for group in groups.values():
        canonical = min(
            group,
            key=lambda u: (_canonical_host_rank(urlparse(u).hostname or ""), u.lower()),
        )
        kept.append(canonical.rstrip("/"))
        for u in group:
            norm = u.rstrip("/")
            if norm != canonical.rstrip("/"):
                dropped.append(norm)
    return kept, dropped


def load_dashboard_base_urls(explicit: list[str] | None = None) -> list[str]:
    """Base URLs saved from the dashboard (data/base-urls.json)."""
    if explicit is not None:
        return [u.rstrip("/") for u in explicit if u.strip()]
    try:
        from app.services.base_urls_service import resolved_base_url_strings

        return [u.rstrip("/") for u in resolved_base_url_strings()]
    except Exception:
        return []


def collect_probe_base_urls(raw_config: dict[str, Any] | None) -> list[str]:
    """
    Origins to probe in diagnosis modules (7-x, 3-x, 1-5).

    When the dashboard lists base URLs, only those origins are used so config
    dev targets (localhost:5173, host.docker.internal:8080) do not appear in
    production scan results.

    When the dashboard is empty, fall back to config ``targets`` and
    ``inventory.markdown.frontend_base_url`` for local/dev setups.
    """
    dashboard_bases = load_dashboard_base_urls()
    if dashboard_bases:
        return list(dashboard_bases)

    bases: list[str] = []
    seen: set[str] = set()
    raw = raw_config or {}
    for t in raw.get("targets") or []:
        if isinstance(t, dict) and t.get("base_url"):
            url = str(t["base_url"]).rstrip("/")
            if url and url not in seen:
                bases.append(url)
                seen.add(url)

    inv = raw.get("inventory") or {}
    md = inv.get("markdown") or {}
    fe = str(md.get("frontend_base_url") or "").rstrip("/")
    if fe and fe not in seen:
        bases.append(fe)

    return bases


def probe_base_key(url: str) -> str:
    return url.rstrip("/").lower()


def probe_base_keys(bases: list[str]) -> frozenset[str]:
    return frozenset(probe_base_key(b) for b in bases if str(b).strip())


def endpoint_on_probe_base(base_url: str, probe_bases: list[str]) -> bool:
    """True when endpoint origin is included in dashboard/config probe bases."""
    if not probe_bases:
        return True
    return probe_base_key(base_url) in probe_base_keys(probe_bases)


def filter_endpoints_by_probe_bases(
    endpoints: list[Any],
    raw_config: dict[str, Any] | None,
) -> list[Any]:
    """Keep api-tree rows whose ``base_url`` matches ``collect_probe_base_urls``."""
    bases = collect_probe_base_urls(raw_config)
    if not bases:
        return list(endpoints)
    keys = probe_base_keys(bases)
    return [ep for ep in endpoints if probe_base_key(getattr(ep, "base_url", "") or "") in keys]


def _login_entry_base_url(entry: dict[str, Any]) -> str:
    base = str(entry.get("base_url") or "").rstrip("/")
    if base:
        return base
    parsed = urlparse(str(entry.get("url") or ""))
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def login_url_identity_key(url: str) -> tuple[str, int, str]:
    """Logical login endpoint key — host aliases (localhost vs Docker) share one key."""
    parsed = urlparse(str(url or "").rstrip("/"))
    port = parsed.port
    if port is None:
        port = 443 if (parsed.scheme or "http") == "https" else 80
    path = (parsed.path or "/").rstrip("/") or "/"
    return ((parsed.scheme or "http").lower(), port, path.lower())


def canonical_login_url(url: str) -> str:
    """Probe-ready URL for lists/reports; rewrites localhost when ARGUS_PROBE_HOST is set."""
    from inventory.net import probe_url

    cleaned = str(url or "").strip().rstrip("/")
    if not cleaned:
        return ""
    return probe_url(cleaned)


def _login_entry_label(url: str, *, multi: bool) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    tail = path.split("/")[-1] or "login"
    if not multi:
        return tail
    host = parsed.netloc or url
    return f"{host}·{tail}"


def dedupe_login_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse localhost / host.docker.internal duplicates to one probe-facing URL."""
    source_rank = {"dashboard": 0, "config": 1, "inventory": 2}
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}

    for entry in entries:
        raw_url = str(entry.get("url") or "").strip()
        if not raw_url:
            continue
        canon = canonical_login_url(raw_url)
        key = login_url_identity_key(canon)
        normalized = dict(entry)
        normalized["url"] = canon
        parsed = urlparse(canon)
        normalized["base_url"] = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

        prev = by_key.get(key)
        if prev is None:
            by_key[key] = normalized
            continue
        if source_rank.get(str(normalized.get("source") or ""), 3) < source_rank.get(
            str(prev.get("source") or ""), 3
        ):
            by_key[key] = normalized

    multi = len(by_key) > 1
    out: list[dict[str, Any]] = []
    for item in by_key.values():
        row = dict(item)
        row["label"] = _login_entry_label(str(row["url"]), multi=multi)
        out.append(row)
    return sorted(out, key=lambda e: (source_rank.get(e.get("source", ""), 3), e.get("url", "")))


def filter_login_entries_by_probe_bases(
    entries: list[dict[str, Any]],
    raw_config: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Keep login rows on dashboard/config probe origins."""
    bases = collect_probe_base_urls(raw_config)
    if not bases:
        return list(entries)
    base_keys = {_origin_dedupe_key(b) for b in bases}
    out: list[dict[str, Any]] = []
    for entry in entries:
        base = _login_entry_base_url(entry)
        if base and _origin_dedupe_key(base) in base_keys:
            out.append(entry)
    return out


def filter_login_entry_report(
    report: dict[str, Any] | None,
    raw_config: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not report:
        return report
    entries = report.get("login_entries")
    if not isinstance(entries, list):
        return report
    filtered = filter_login_entries_by_probe_bases(entries, raw_config)
    if filtered == entries:
        return report
    out = dict(report)
    out["login_entries"] = filtered
    return out


def _config_fallback_base_url(raw_config: dict[str, Any] | None) -> str:
    """Legacy fallbacks when dashboard base URLs are not configured yet."""
    raw = raw_config or {}

    inv = raw.get("inventory") or {}
    md = inv.get("markdown") or {}
    if md.get("frontend_base_url"):
        return str(md["frontend_base_url"]).rstrip("/")

    targets = raw.get("targets") or []
    for t in targets:
        if isinstance(t, dict) and t.get("base_url"):
            url = str(t["base_url"])
            if ":5173" in url or ":5174" in url or "frontend" in str(t.get("name", "")).lower():
                return url.rstrip("/")

    for t in targets:
        if isinstance(t, dict) and t.get("base_url"):
            return str(t["base_url"]).rstrip("/")

    return "http://localhost:5173"


def pick_public_base_for_url(
    url: str,
    *,
    raw_config: dict[str, Any] | None = None,
    dashboard_bases: list[str] | None = None,
) -> str:
    """
    Pick the dashboard base URL that best matches a probe URL (port-first).
    Used when mapping host.docker.internal:5173 → user's saved http://localhost:5173.
    """
    bases = load_dashboard_base_urls(dashboard_bases)
    if not bases:
        return _config_fallback_base_url(raw_config)

    parsed = urlparse(url)
    probe_port = parsed.port
    probe_host = parsed.hostname or ""

    if probe_host in DOCKER_HOST_ALIASES and probe_port is not None:
        for base in bases:
            bp = urlparse(base)
            if bp.port == probe_port:
                return base.rstrip("/")
        for base in bases:
            bp = urlparse(base)
            if bp.port is None and probe_port in (80, 443):
                return base.rstrip("/")

    for base in bases:
        bp = urlparse(base)
        if bp.port in FRONTEND_PORTS:
            return base.rstrip("/")

    return bases[0].rstrip("/")


def resolve_public_base_url(
    raw_config: dict[str, Any] | None = None,
    *,
    dashboard_bases: list[str] | None = None,
) -> str:
    """
    Default public browser base for replay metadata.
    Priority: dashboard Base URLs → config inventory/targets → localhost.
    """
    bases = load_dashboard_base_urls(dashboard_bases)
    if bases:
        for base in bases:
            bp = urlparse(base)
            if bp.port in FRONTEND_PORTS:
                return base.rstrip("/")
        return bases[0].rstrip("/")
    return _config_fallback_base_url(raw_config)


def normalize_url(
    url: str,
    *,
    public_base_url: str = "",
    raw_config: dict[str, Any] | None = None,
    dashboard_bases: list[str] | None = None,
) -> str:
    """Map docker-internal hosts to the user's dashboard base URL (port-aware)."""
    if not url:
        return url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in DOCKER_HOST_ALIASES:
        return url

    bases = load_dashboard_base_urls(dashboard_bases)
    matched_base = ""

    if parsed.port is not None and bases:
        for base in bases:
            bp = urlparse(base)
            if bp.port == parsed.port:
                matched_base = base.rstrip("/")
                break

    if not matched_base:
        matched_base = (
            public_base_url
            or pick_public_base_for_url(url, raw_config=raw_config, dashboard_bases=dashboard_bases)
        ).rstrip("/")

    public_parsed = urlparse(matched_base if "://" in matched_base else f"http://{matched_base}")
    new_host = public_parsed.hostname or "localhost"
    port = public_parsed.port
    netloc = f"{new_host}:{port}" if port else new_host
    return urlunparse(parsed._replace(netloc=netloc))


def resolve_login_url(
    raw_config: dict[str, Any] | None,
    *,
    dashboard_bases: list[str] | None = None,
) -> str:
    _ = dashboard_bases
    from app.services.login_discovery_service import resolve_login_entries

    raw = raw_config or {}
    auth = raw.get("auth") or {}
    entries = resolve_login_entries(auth, raw)
    if entries:
        return str(entries[0]["url"])
    return ""


def auth_config_from_raw(
    raw_config: dict[str, Any] | None,
    account_auth: dict[str, Any] | None,
    *,
    dashboard_bases: list[str] | None = None,
) -> dict[str, str]:
    raw = raw_config or {}
    auth = raw.get("auth") or {}
    acct = account_auth or {}
    return {
        "login_url": resolve_login_url(raw, dashboard_bases=dashboard_bases),
        "account_email": str(acct.get("email") or ""),
        "delivery": str(auth.get("delivery") or acct.get("delivery") or "cookie"),
        "cookie_name": str(auth.get("cookie_name") or acct.get("cookie_name") or "accessToken"),
        "id_field": str(auth.get("id_field") or "email"),
        "pw_field": str(auth.get("pw_field") or "password"),
    }
