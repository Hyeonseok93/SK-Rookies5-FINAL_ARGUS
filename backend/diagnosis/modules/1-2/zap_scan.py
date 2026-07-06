"""ZAP injection scan phase — wraps branch ZapEngine with ARGUS proxy discovery."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.zap_util import ZapNotAvailableError, ensure_zap_proxy, probe_url
from diagnosis.replay.normalize import FRONTEND_PORTS, collect_probe_base_urls
from inventory.load import find_openapi_spec


def _proxy_host_port(proxy_url: str) -> tuple[str, str]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 8090)
    return host, port


def _api_probe_bases(bases: list[str]) -> list[str]:
    api_bases: list[str] = []
    seen: set[tuple[str, int]] = set()
    for base in bases:
        url = base.rstrip("/")
        if not url:
            continue
        parsed = urlparse(url)
        port = parsed.port
        if port is None:
            port = 443 if (parsed.scheme or "http") == "https" else 80
        if port in FRONTEND_PORTS:
            continue
        key = (parsed.hostname or "", port)
        if key in seen:
            continue
        seen.add(key)
        api_bases.append(url)
    return api_bases


def run_zap_injection_phase(
    raw_config: dict[str, Any],
    data_dir: Any,
    *,
    jwt_token: str = "",
    session_headers: dict[str, str] | None = None,
    max_minutes: int = 20,
    progress_cb: Any | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Run Spider + Active Scan (injection policy) on each API base. Returns DetectionResult list."""
    from zap_engine import ZapEngine

    bases = _api_probe_bases(collect_probe_base_urls(raw_config))
    if not bases:
        return [], {"error": "no_base_urls"}

    zap_cfg = raw_config.get("zap") or {}
    try:
        proxy_url = ensure_zap_proxy(zap_cfg)
    except ZapNotAvailableError as exc:
        return [], {"error": str(exc)}

    api_key = str(zap_cfg.get("api_key") or "argus_secret_key")
    host, port = _proxy_host_port(proxy_url)
    engine = ZapEngine(proxy_address=f"{host}:{port}", api_key=api_key)

    spec_path = find_openapi_spec(data_dir)
    swagger_url = str(spec_path.resolve()) if spec_path is not None else ""
    primary_target = probe_url(bases[0])

    engine.configure_scan(
        target_url=primary_target,
        swagger_url=swagger_url,
        jwt_token=jwt_token,
        session_headers=session_headers,
    )

    all_results: list[Any] = []
    scanned_targets: list[str] = []
    per_base_minutes = max(5, int(max_minutes / max(len(bases), 1)))
    zap_total = max(len(bases) * 100, 1)
    for idx, base in enumerate(bases):
        target_url = probe_url(base.rstrip("/"))
        scanned_targets.append(target_url)

        def _zap_progress(status: int, current_url: str, base_idx: int = idx) -> None:
            done = min(zap_total, base_idx * 100 + max(0, min(int(status), 100)))
            if progress_cb:
                progress_cb(done, zap_total, current_url, int(status))

        zap_results = engine.run_active_scan(
            target_url=target_url,
            max_minutes=per_base_minutes,
            progress_cb=_zap_progress,
        )
        all_results.extend(zap_results)

    deduped: list[Any] = []
    seen: set[tuple[Any, ...]] = set()
    for result in all_results:
        key = (result.method, result.url, result.param, result.injection_type, result.plugin_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(result)

    return deduped, {
        "target_urls": scanned_targets,
        "swagger_path": swagger_url or None,
        "zap_alerts": len(deduped),
        "proxy": proxy_url,
        "cookie_auth": bool((session_headers or {}).get("Cookie") or (session_headers or {}).get("cookie")),
    }
