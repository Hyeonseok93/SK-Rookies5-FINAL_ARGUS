"""Thin ZAP adapter for ARGUS 1-1."""

from __future__ import annotations


def connect_zap(proxy_url: str = "http://127.0.0.1:8090", api_key: str = ""):
    from zapv2 import ZAPv2

    proxies = {"http": proxy_url, "https": proxy_url}
    return ZAPv2(apikey=api_key, proxies=proxies)


def collect_zap_alerts(zap, base_url: str) -> list[dict]:
    try:
        raw_alerts = zap.core.alerts(baseurl=base_url) or []
    except Exception:
        return []
    allowed_plugin_ids = {"40012", "40014", "40016", "40017"}
    filtered = []
    for alert in raw_alerts:
        plugin_id = str(alert.get("pluginId", ""))
        if plugin_id not in allowed_plugin_ids:
            continue
        if plugin_id in {"40012", "40014"} and str(alert.get("confidence", "")).lower() == "low":
            message_id = alert.get("messageId")
            is_safe_json_context = False
            if message_id:
                try:
                    message = zap.core.message(message_id)
                    response_header = str(message.get("responseHeader", "")).lower()
                    if "application/json" in response_header and "nosniff" in response_header:
                        is_safe_json_context = True
                except Exception:
                    pass
            if is_safe_json_context:
                continue
        filtered.append(alert)
    return filtered


def apply_auth_to_zap(zap, token: str | None = None, cookie_header: str = "") -> None:
    if not zap:
        return
    try:
        zap.replacer.remove_rule("ARGUS Authorization")
    except Exception:
        pass
    try:
        zap.replacer.remove_rule("ARGUS Cookie")
    except Exception:
        pass
    if token:
        zap.replacer.add_rule("ARGUS Authorization", True, "REQ_HEADER", False, "Authorization", f"Bearer {token}")
    if cookie_header:
        zap.replacer.add_rule("ARGUS Cookie", True, "REQ_HEADER", False, "Cookie", cookie_header)
