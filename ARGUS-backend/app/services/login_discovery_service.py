"""Discover login endpoints from inventory (api-tree) for auth probes and 6-2."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls, probe_base_key, probe_base_keys
from app.services.zap_util import probe_url
from inventory.schema import ApiTree, Endpoint, build_full_url
from inventory.load import load_api_tree
from app.workspace import require_data_dir


def _load_raw_config() -> dict[str, Any]:
    import os

    import yaml

    from app.config import BACKEND_ROOT

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    if config_path.is_file():
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return {}



LOGIN_PATH_POSITIVE = re.compile(
    r"(?i)(/(auth/)?(login|signin|sign-in|authenticate)(/|$)|/login$)"
)
LOGIN_PATH_NEGATIVE = re.compile(
    r"(?i)(refresh|logout|sign-?up|register|password|reset|forgot|verify|"
    r"check-email|check-nickname|email/send|email/verify|token|oauth|callback|"
    r"mfa|2fa|captcha|session)"
)

ID_FIELD_ALIASES = frozenset(
    {"email", "username", "user", "login", "id", "account", "userid", "user_id"}
)
PW_FIELD_ALIASES = frozenset(
    {"password", "passwd", "pass", "pwd", "secret", "credential"}
)


def _body_param_names(ep: Endpoint) -> set[str]:
    return {
        p.name.lower()
        for p in ep.request_params
        if p.in_ in ("body", "form")
    }


def _has_credential_fields(ep: Endpoint, auth_cfg: dict[str, Any]) -> bool:
    names = _body_param_names(ep)
    id_field = str(auth_cfg.get("id_field") or "email").lower()
    pw_field = str(auth_cfg.get("pw_field") or "password").lower()
    has_id = id_field in names or bool(names & ID_FIELD_ALIASES)
    has_pw = pw_field in names or bool(names & PW_FIELD_ALIASES)
    return has_id and has_pw


def _path_looks_like_login(path: str) -> bool:
    clean = path.split("?")[0]
    if LOGIN_PATH_NEGATIVE.search(clean):
        return False
    return bool(LOGIN_PATH_POSITIVE.search(clean))


def _strong_login_path(path: str) -> bool:
    lower = path.split("?")[0].lower().rstrip("/")
    return (
        lower.endswith("/auth/login")
        or lower.endswith("/login")
        or "/auth/admin/login" in lower
        or lower.endswith("/signin")
        or lower.endswith("/sign-in")
    )


def is_login_candidate(ep: Endpoint, auth_cfg: dict[str, Any]) -> bool:
    if ep.method.upper() != "POST":
        return False
    path = ep.path.split("?")[0]
    if not _path_looks_like_login(path):
        return False
    if _has_credential_fields(ep, auth_cfg):
        return True
    return _strong_login_path(path)


def _preferred_bases(raw_config: dict[str, Any] | None) -> set[str]:
    return set(probe_base_keys(collect_probe_base_urls(raw_config)))


def _base_score(base_url: str, ep: Endpoint, preferred_bases: set[str]) -> int:
    score = 0
    base = base_url.rstrip("/")
    if base in preferred_bases:
        score += 10
    if ep.kind == "api":
        score += 5
    parsed = urlparse(base)
    port = parsed.port
    if port in (8080, 8081, 8000, 3000):
        score += 3
    if port == 5173:
        score -= 4
    if "frontend" in (ep.sources or []):
        score -= 2
    return score


def _entry_label(url: str, *, multi: bool) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    tail = path.split("/")[-1] or "login"
    if not multi:
        return tail
    host = parsed.netloc or url
    return f"{host}·{tail}"


def discover_login_entries(
    auth_cfg: dict[str, Any] | None = None,
    raw_config: dict[str, Any] | None = None,
    *,
    data_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Return deduplicated login POST endpoints from inventory."""
    auth_cfg = auth_cfg or {}
    if raw_config is None:
        raw_config = _load_raw_config()

    tree = load_api_tree(require_data_dir(data_dir))
    if not tree or not tree.endpoints:
        return []

    probe_bases = collect_probe_base_urls(raw_config)
    probe_keys = probe_base_keys(probe_bases) if probe_bases else None
    preferred = _preferred_bases(raw_config)
    best_by_path: dict[tuple[str, str], tuple[Endpoint, int]] = {}

    for ep in tree.endpoints:
        if probe_keys is not None and probe_base_key(ep.base_url) not in probe_keys:
            continue
        if not is_login_candidate(ep, auth_cfg):
            continue
        path_key = ep.path.split("?")[0].lower()
        origin_key = probe_base_key(ep.base_url)
        key = (ep.method.upper(), path_key, origin_key)
        score = _base_score(ep.base_url, ep, preferred)
        prev = best_by_path.get(key)
        if prev is None or score > prev[1]:
            best_by_path[key] = (ep, score)

    ranked = sorted(best_by_path.values(), key=lambda item: (-item[1], item[0].path))
    multi = len(ranked) > 1
    entries: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    for ep, _score in ranked:
        full = probe_url(build_full_url(ep.base_url, ep.path))
        if full in seen_urls:
            continue
        seen_urls.add(full)
        entries.append(
            {
                "url": full,
                "label": _entry_label(full, multi=multi),
                "base_url": ep.base_url.rstrip("/"),
                "source": "inventory",
                "kind": "api",
                "method": ep.method.upper(),
                "path": ep.path.split("?")[0],
            }
        )

    return entries


def resolve_login_entries(
    auth_cfg: dict[str, Any] | None = None,
    raw_config: dict[str, Any] | None = None,
    *,
    data_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Inventory auto-discovery + dashboard-prepared login endpoints (deduped by URL)."""
    auth_cfg = auth_cfg or {}
    if raw_config is None:
        raw_config = _load_raw_config()

    from app.services.login_endpoints_service import dashboard_login_entries
    from diagnosis.replay.normalize import dedupe_login_entries, filter_login_entries_by_probe_bases

    collected: list[dict[str, str]] = []
    explicit_urls = auth_cfg.get("login_urls") or []
    if isinstance(explicit_urls, str):
        explicit_urls = [explicit_urls]
    for raw_url in explicit_urls:
        url = str(raw_url or "").strip().rstrip("/")
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        collected.append(
            {
                "url": url,
                "label": _entry_label(url, multi=True),
                "base_url": f"{parsed.scheme}://{parsed.netloc}",
                "source": "config",
                "kind": "api",
                "method": "POST",
                "path": parsed.path or "/",
            }
        )
    collected.extend(discover_login_entries(auth_cfg, raw_config, data_dir=data_dir))
    collected.extend(dashboard_login_entries(raw_config, data_dir=data_dir))
    merged = dedupe_login_entries(collected)
    return filter_login_entries_by_probe_bases(merged, raw_config)
