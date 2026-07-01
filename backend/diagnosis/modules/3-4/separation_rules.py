"""Guideline 3-4 — admin/user separation heuristics (inventory + login report)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from diagnosis.replay.normalize import probe_base_key, probe_base_keys
from diagnosis.result import DiagnosisFinding
from inventory.schema import ApiTree, Endpoint

GUESSABLE_PATH_RE = re.compile(
    r"(?i)(^|/)(admin|master|manager|manage|console|backoffice|cms|webmaster|administrator|root)(/|$|\.|-)"
)

ADMIN_LOGIN_PATH_RE = re.compile(
    r"(?i)(/auth/admin/login|/admin/login|/admin/signin|/admin/sign-in|login/admin)"
)

ADMIN_SUBDOMAIN_PREFIXES = frozenset(
    {
        "admin",
        "master",
        "manager",
        "manage",
        "console",
        "backoffice",
        "cms",
        "operator",
        "control",
    }
)

ADMIN_API_PREFIXES = ("/api/v1/admin", "/admin-api/", "/v1/admin/")


def parse_host_port(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url.rstrip("/"))
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme or "http"
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return host, scheme, port


def origin_key(url: str) -> str:
    host, scheme, port = parse_host_port(url)
    return f"{scheme}://{host}:{port}"


def registrable_domain(host: str) -> str:
    host = (host or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def classify_login_entry(entry: dict[str, Any]) -> str:
    """Return 'admin' or 'user' for a configured login entry."""
    url = str(entry.get("url") or "")
    label = str(entry.get("label") or "").lower()
    path = urlparse(url).path.lower()
    if ADMIN_LOGIN_PATH_RE.search(path):
        return "admin"
    if label in ("admin", "administrator", "manager"):
        return "admin"
    if "/admin/" in path or path.rstrip("/").endswith("/admin"):
        return "admin"
    return "user"


def is_admin_subdomain_host(host: str) -> bool:
    host = (host or "").lower().split(":")[0]
    parts = host.split(".")
    if len(parts) < 3:
        return False
    return parts[0] in ADMIN_SUBDOMAIN_PREFIXES


def admin_subdomain_pairs(admin_hosts: set[str], user_hosts: set[str]) -> list[tuple[str, str]]:
    """admin.onde.click paired with onde.click / www.onde.click on same registrable domain."""
    pairs: list[tuple[str, str]] = []
    for ah in sorted(admin_hosts):
        if not is_admin_subdomain_host(ah):
            continue
        admin_domain = registrable_domain(ah)
        for uh in sorted(user_hosts):
            if uh == ah:
                continue
            if is_admin_subdomain_host(uh):
                continue
            if registrable_domain(uh) == admin_domain:
                pairs.append((uh, ah))
    return pairs


def guessable_path_tokens(path: str) -> list[str]:
    return list({m.group(2).lower() for m in GUESSABLE_PATH_RE.finditer(path or "")})


def is_admin_api_path(path: str) -> bool:
    lower = (path or "").lower()
    return any(p in lower for p in ADMIN_API_PREFIXES) or "/admin/" in lower


def is_admin_frontend_path(path: str) -> bool:
    clean = (path or "").split("?")[0].lower()
    if not clean.startswith("/"):
        clean = f"/{clean}"
    if clean.startswith("/admin") or clean.startswith("/admin/"):
        return True
    return bool(guessable_path_tokens(clean))


def is_user_frontend_path(path: str) -> bool:
    clean = (path or "").split("?")[0].lower()
    if is_admin_frontend_path(clean):
        return False
    if is_admin_api_path(clean):
        return False
    return True


@dataclass
class InventorySlice:
    user_frontend_bases: set[str] = field(default_factory=set)
    admin_frontend_rows: list[dict[str, str]] = field(default_factory=list)
    admin_api_rows: list[dict[str, str]] = field(default_factory=list)
    guessable_paths: list[dict[str, str]] = field(default_factory=list)
    all_bases: set[str] = field(default_factory=set)
    admin_hosts: set[str] = field(default_factory=set)
    user_hosts: set[str] = field(default_factory=set)


def slice_inventory(tree: ApiTree | None, extra_bases: list[str] | None = None) -> InventorySlice:
    out = InventorySlice()
    for base in extra_bases or []:
        if base:
            out.all_bases.add(base.rstrip("/"))
            host, _, _ = parse_host_port(base)
            out.user_hosts.add(host)

    if tree is None:
        return out

    allowed_keys = probe_base_keys(extra_bases) if extra_bases else None

    for ep in tree.endpoints:
        base = (ep.base_url or "").rstrip("/")
        if allowed_keys is not None and probe_base_key(base) not in allowed_keys:
            continue
        if base:
            out.all_bases.add(base)
            host, _, _ = parse_host_port(base)

        path = ep.path or ""
        if ep.kind == "frontend":
            if is_admin_frontend_path(path):
                out.admin_frontend_rows.append(
                    {"base_url": base, "path": path, "method": ep.method.upper()}
                )
                if base:
                    out.admin_hosts.add(host)
                tokens = guessable_path_tokens(path)
                if tokens:
                    out.guessable_paths.append(
                        {"base_url": base, "path": path, "tokens": ",".join(tokens)}
                    )
            elif is_user_frontend_path(path) and base:
                out.user_frontend_bases.add(base)
                out.user_hosts.add(host)
        elif is_admin_api_path(path):
            out.admin_api_rows.append({"base_url": base, "path": path, "method": ep.method.upper()})
            if base:
                out.admin_hosts.add(host)
            tokens = guessable_path_tokens(path)
            if tokens:
                out.guessable_paths.append(
                    {"base_url": base, "path": path, "tokens": ",".join(tokens)}
                )

    return out


def _finding(
    *,
    severity: str,
    rule_id: str,
    trigger: str,
    message: str,
    meta: dict[str, Any],
) -> DiagnosisFinding:
    return DiagnosisFinding(
        severity=severity,
        message=message,
        evidence={
            "rule_id": rule_id,
            "trigger": trigger,
            "engine": "inventory",
            "analysis_mode": "static",
            **meta,
        },
    )


def analyze_separation(
    *,
    login_entries: list[dict[str, Any]],
    inventory: InventorySlice,
    extra_admin_hosts: list[str] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "login_entries": len(login_entries),
        "admin_frontend_paths": len(inventory.admin_frontend_rows),
        "admin_api_paths": len(inventory.admin_api_rows),
    }

    user_logins = [e for e in login_entries if classify_login_entry(e) == "user"]
    admin_logins = [e for e in login_entries if classify_login_entry(e) == "admin"]
    stats["user_login_entries"] = len(user_logins)
    stats["admin_login_entries"] = len(admin_logins)

    user_login_hosts = {parse_host_port(e["url"])[0] for e in user_logins if e.get("url")}
    admin_login_hosts = {parse_host_port(e["url"])[0] for e in admin_logins if e.get("url")}
    for h in extra_admin_hosts or []:
        if h:
            admin_login_hosts.add(h.lower().split(":")[0])
            inventory.admin_hosts.add(h.lower().split(":")[0])

    inventory.user_hosts.update(user_login_hosts)

    # Positive: admin subdomain (admin.onde.click vs onde.click)
    subdomain_pairs = admin_subdomain_pairs(inventory.admin_hosts | admin_login_hosts, inventory.user_hosts | user_login_hosts)
    stats["admin_subdomain_pairs"] = [{"user_host": u, "admin_host": a} for u, a in subdomain_pairs]
    if subdomain_pairs:
        for user_host, admin_host in subdomain_pairs:
            findings.append(
                _finding(
                    severity="info",
                    rule_id="3-4-host-separated",
                    trigger="admin_subdomain",
                    message=f"Admin host separated by subdomain: {admin_host} (user: {user_host})",
                    meta={
                        "user_host": user_host,
                        "admin_host": admin_host,
                        "registrable_domain": registrable_domain(admin_host),
                        "related_sections": ["3-4"],
                    },
                )
            )

    # Same login URL for user and admin
    user_urls = {str(e.get("url") or "").rstrip("/") for e in user_logins}
    admin_urls = {str(e.get("url") or "").rstrip("/") for e in admin_logins}
    shared_login_urls = sorted(user_urls & admin_urls)
    if shared_login_urls:
        findings.append(
            _finding(
                severity="high",
                rule_id="3-4-same-login-url",
                trigger="identical_login_url",
                message=f"User and admin share the same login URL ({len(shared_login_urls)} entry)",
                meta={"urls": shared_login_urls, "related_sections": ["3-4"]},
            )
        )
    stats["shared_login_urls"] = shared_login_urls

    # Login service same host:port (path-only separation)
    if user_logins and admin_logins and not shared_login_urls:
        user_origins = {origin_key(e["url"]) for e in user_logins if e.get("url")}
        admin_origins = {origin_key(e["url"]) for e in admin_logins if e.get("url")}
        shared_origins = sorted(user_origins & admin_origins)
        if shared_origins and not subdomain_pairs:
            findings.append(
                _finding(
                    severity="medium",
                    rule_id="3-4-login-same-host",
                    trigger="login_same_origin",
                    message=(
                        "User and admin login APIs share the same host:port "
                        "(path-only separation)"
                    ),
                    meta={
                        "origins": shared_origins,
                        "user_login_urls": [e.get("url") for e in user_logins],
                        "admin_login_urls": [e.get("url") for e in admin_logins],
                        "related_sections": ["3-4"],
                    },
                )
            )
        stats["shared_login_origins"] = shared_origins

    # Admin UI on same base as user frontend (SPA /admin on user host)
    same_server_admin_ui: list[dict[str, str]] = []
    for row in inventory.admin_frontend_rows:
        base = row["base_url"]
        if base in inventory.user_frontend_bases:
            same_server_admin_ui.append(row)
    if same_server_admin_ui and not subdomain_pairs:
        sample = same_server_admin_ui[:5]
        findings.append(
            _finding(
                severity="medium",
                rule_id="3-4-ui-same-server",
                trigger="admin_ui_same_base",
                message=(
                    f"Admin UI paths served on the same base URL as user frontend "
                    f"({len(same_server_admin_ui)} path(s))"
                ),
                meta={
                    "samples": sample,
                    "total": len(same_server_admin_ui),
                    "related_sections": ["3-4"],
                },
            )
        )
    stats["admin_ui_same_base"] = len(same_server_admin_ui)

    # Admin API on same origin as user API bases (8080 shared)
    user_api_bases = {
        b for b in inventory.all_bases if b and not b.rstrip("/").endswith(("5173", "5174", "3000"))
    }
    admin_api_same: list[dict[str, str]] = []
    for row in inventory.admin_api_rows:
        base = row["base_url"]
        if any(origin_key(base) == origin_key(u) for u in user_api_bases):
            admin_api_same.append(row)
    if admin_api_same and not subdomain_pairs:
        findings.append(
            _finding(
                severity="medium",
                rule_id="3-4-api-same-server",
                trigger="admin_api_same_origin",
                message=(
                    f"Admin API paths on the same server origin as user APIs "
                    f"({len(admin_api_same)} path(s))"
                ),
                meta={
                    "samples": admin_api_same[:5],
                    "total": len(admin_api_same),
                    "related_sections": ["3-4"],
                },
            )
        )
    stats["admin_api_same_origin"] = len(admin_api_same)

    # Guessable path tokens (path-based — not subdomain)
    seen_guess: set[tuple[str, str]] = set()
    guessable_samples: list[dict[str, str]] = []
    for row in inventory.guessable_paths:
        key = (row["base_url"], row["path"])
        if key in seen_guess:
            continue
        seen_guess.add(key)
        guessable_samples.append(row)
    if guessable_samples:
        findings.append(
            _finding(
                severity="info",
                rule_id="3-4-guessable-path",
                trigger="guessable_admin_token",
                message=(
                    f"Easily guessable admin-related path tokens in inventory "
                    f"({len(guessable_samples)} path(s))"
                ),
                meta={
                    "samples": guessable_samples[:12],
                    "total": len(guessable_samples),
                    "tokens": sorted({t for r in guessable_samples for t in r.get("tokens", "").split(",") if t}),
                    "related_sections": ["3-4"],
                },
            )
        )
    stats["guessable_paths"] = len(guessable_samples)

    return findings, stats
