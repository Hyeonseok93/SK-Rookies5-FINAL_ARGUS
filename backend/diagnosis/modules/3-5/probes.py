"""HTTP inventory probes for search-engine signals (3-5)."""

from __future__ import annotations

from typing import Any, Callable

import httpx

from diagnosis.result import DiagnosisFinding


def _fetch(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int | None, str, str, str, str | None]:
    headers = {
        "User-Agent": "ARGUS-3-5/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        )
        body = resp.text[:120_000]
        return (
            resp.status_code,
            body,
            resp.headers.get("content-type", ""),
            resp.headers.get("x-robots-tag", ""),
            None,
        )
    except httpx.HTTPError as exc:
        return None, "", "", "", str(exc)[:200]


def run_robots_inventory(
    bases: list[str],
    *,
    probe_base_fn: Callable[[str], str],
    parse_robots_fn: Any,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """robots.txt is always fetched anonymously (public)."""
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "robots_probed": 0,
        "robots_present": 0,
        "robots_missing": 0,
        "disallow_rules_total": 0,
    }

    with httpx.Client() as client:
        for base in bases:
            probe_base = probe_base_fn(base)
            url = f"{probe_base.rstrip('/')}/robots.txt"
            stats["robots_probed"] += 1
            if on_progress:
                on_progress(
                    endpoints_done=stats["robots_probed"],
                    endpoints_total=len(bases),
                    endpoint_id=base[:80],
                )
            status, body, _ct, _xr, err = _fetch(client, url, timeout=timeout)

            if err:
                findings.append(
                    DiagnosisFinding(
                        severity="info",
                        message=f"[3-5] robots.txt unreachable: {base}",
                        evidence={
                            "rule_id": "3-5-search-engine",
                            "engine": "httpx",
                            "kind": "robots_txt",
                            "auth_mode": "anonymous",
                            "base_url": base,
                            "url": url,
                            "trigger": "robots_unreachable",
                            "error": err,
                        },
                    )
                )
                continue

            info = parse_robots_fn(body, status=status)
            if info.present:
                stats["robots_present"] += 1
                stats["disallow_rules_total"] += len(info.disallow_paths)
                message = (
                    f"[3-5] robots.txt present at `{base}` — "
                    f"Disallow {len(info.disallow_paths)}, Allow {len(info.allow_paths)}, "
                    f"Sitemap {len(info.sitemaps)}"
                )
                trigger = "robots_txt_present"
            else:
                stats["robots_missing"] += 1
                message = f"[3-5] robots.txt not found at `{base}` (HTTP {status})"
                trigger = "robots_txt_absent"

            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message=message,
                    evidence={
                        "rule_id": "3-5-search-engine",
                        "engine": "httpx",
                        "kind": "robots_txt",
                        "auth_mode": "anonymous",
                        "base_url": base,
                        "url": url,
                        "http_status": status,
                        "trigger": trigger,
                        "present": info.present,
                        "disallow_paths": info.disallow_paths,
                        "allow_paths": info.allow_paths,
                        "sitemaps": info.sitemaps,
                        "user_agents": info.user_agents,
                        "body_excerpt": info.body_excerpt if info.present else None,
                    },
                )
            )

    return findings, stats


def run_page_inventory(
    probe_targets: list[dict[str, str]],
    *,
    extract_signals_fn: Any,
    auth_mode: str = "anonymous",
    request_headers: dict[str, str] | None = None,
    account_email: str | None = None,
    login_label: str | None = None,
    login_url: str | None = None,
    timeout: float = 8.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "auth_mode": auth_mode,
        "pages_probed": 0,
        "unreachable": 0,
        "with_noindex": 0,
        "with_nofollow": 0,
        "with_any_robots_directive": 0,
        "without_robots_directive": 0,
        "noindex_urls": [],
        "nofollow_urls": [],
        "indexable_urls": [],
    }

    with httpx.Client() as client:
        for target in probe_targets:
            stats["pages_probed"] += 1
            url = target["probe_url"]
            base_url = target.get("base_url") or url
            label = target.get("label") or url
            path = target.get("path") or "/"

            if on_progress:
                on_progress(
                    endpoints_done=stats["pages_probed"],
                    endpoints_total=len(probe_targets),
                    endpoint_id=label[:80],
                )

            status, body, content_type, x_robots, err = _fetch(
                client, url, timeout=timeout, extra_headers=request_headers
            )
            if err:
                stats["unreachable"] += 1
                continue

            signals = extract_signals_fn(
                url,
                http_status=status,
                content_type=content_type,
                body=body,
                x_robots=x_robots,
            )
            if signals is None:
                continue

            if not signals.has_any_directive:
                stats["without_robots_directive"] += 1
                if len(stats["indexable_urls"]) < 30:
                    stats["indexable_urls"].append(url)
                continue

            stats["with_any_robots_directive"] += 1
            parts: list[str] = []
            if signals.has_noindex:
                stats["with_noindex"] += 1
                stats["noindex_urls"].append(url)
                parts.append("noindex")
            if signals.has_nofollow:
                stats["with_nofollow"] += 1
                if url not in stats["nofollow_urls"]:
                    stats["nofollow_urls"].append(url)
                parts.append("nofollow")

            directive_label = ", ".join(parts) if parts else "robots directive"
            prefix = f"[3-5][{auth_mode}]"
            ev_base: dict[str, Any] = {
                "rule_id": "3-5-search-engine",
                "engine": "httpx",
                "kind": "page_robots",
                "auth_mode": auth_mode,
                "account_email": account_email,
                "base_url": base_url,
                "base_kind": target.get("base_kind"),
                "url": url,
                "path": path,
                "http_status": status,
                "content_type": content_type,
                "trigger": "page_robots_directive",
                "has_noindex": signals.has_noindex,
                "has_nofollow": signals.has_nofollow,
                "x_robots_tag": signals.x_robots_tag,
                "meta_robots": signals.meta_robots,
                "meta_raw": signals.meta.raw if signals.meta else None,
                "header_raw": signals.header.raw if signals.header else None,
            }
            if login_label:
                ev_base["login_label"] = login_label
            if login_url:
                ev_base["login_url"] = login_url
            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message=f"{prefix} {directive_label} at `{label}`",
                    evidence=ev_base,
                )
            )

    if stats["pages_probed"]:
        prefix = f"[3-5][{auth_mode}]"
        summary_ev: dict[str, Any] = {
            "rule_id": "3-5-search-engine",
            "engine": "httpx",
            "kind": "page_inventory_summary",
            "auth_mode": auth_mode,
            "account_email": account_email,
            "trigger": "page_inventory_summary",
            **{k: stats[k] for k in (
                "pages_probed", "unreachable", "with_noindex", "with_nofollow",
                "with_any_robots_directive", "without_robots_directive",
                "noindex_urls", "nofollow_urls",
            )},
            "indexable_urls_sample": stats["indexable_urls"],
        }
        if login_label:
            summary_ev["login_label"] = login_label
        if login_url:
            summary_ev["login_url"] = login_url
        findings.insert(
            0,
            DiagnosisFinding(
                severity="info",
                message=(
                    f"{prefix} Page robots inventory — probed {stats['pages_probed']}, "
                    f"noindex {stats['with_noindex']}, nofollow {stats['with_nofollow']}, "
                    f"no directive {stats['without_robots_directive']}"
                ),
                evidence=summary_ev,
            ),
        )

    return findings, stats
