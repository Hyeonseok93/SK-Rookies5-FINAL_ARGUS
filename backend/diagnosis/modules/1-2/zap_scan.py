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


def _api_probe_base(bases: list[str]) -> str:
    for base in bases:
        parsed = urlparse(base)
        port = parsed.port or (443 if (parsed.scheme or "http") == "https" else 80)
        if port not in FRONTEND_PORTS:
            return base.rstrip("/")
    return bases[0].rstrip("/") if bases else ""


def run_zap_injection_phase(
    raw_config: dict[str, Any],
    data_dir: Any,
    *,
    jwt_token: str,
    max_minutes: int = 20,
) -> tuple[list[Any], dict[str, Any]]:
    """Run Spider + Active Scan (injection policy). Returns DetectionResult list."""
    from zap_engine import ZapEngine

    bases = collect_probe_base_urls(raw_config)
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

    target_url = probe_url(_api_probe_base(bases))
    spec_path = find_openapi_spec(data_dir)
    swagger_url = str(spec_path.resolve()) if spec_path is not None else ""

    engine.configure_scan(target_url=target_url, swagger_url=swagger_url, jwt_token=jwt_token)
    zap_results = engine.run_active_scan(target_url=target_url, max_minutes=max_minutes)

    return zap_results, {
        "target_url": target_url,
        "swagger_path": swagger_url or None,
        "zap_alerts": len(zap_results),
        "proxy": proxy_url,
    }
