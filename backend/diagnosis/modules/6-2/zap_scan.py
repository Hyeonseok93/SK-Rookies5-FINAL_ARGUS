"""ZAP active scan rule 40023 (Username Enumeration) for guideline 6-2."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any
from urllib.parse import urlparse

from app.services.zap_util import (
    connect_zap,
    ensure_zap_proxy,
    probe_url,
    reset_zap_workspace,
)
from diagnosis.result import DiagnosisFinding

USERNAME_ENUM_PLUGIN_ID = "40023"
PLUGIN_LABEL = "ZAP Rule 40023 (Possible Username Enumeration)"


def is_username_enum_plugin(plugin_id: str) -> bool:
    return str(plugin_id or "").strip() == USERNAME_ENUM_PLUGIN_ID


def configure_username_enum_scanner(zap: Any) -> None:
    zap.ascan.disable_all_scanners()
    zap.ascan.enable_scanners(USERNAME_ENUM_PLUGIN_ID)
    zap.ascan.set_scanner_alert_threshold(USERNAME_ENUM_PLUGIN_ID, "Medium")
    zap.ascan.set_scanner_attack_strength(USERNAME_ENUM_PLUGIN_ID, "High")


def _auth_method_for_entry(entry: dict[str, str], login_url: str) -> str:
    kind = str(entry.get("kind") or "api").lower()
    if kind == "page":
        return "formBasedAuthentication"
    if "/api/" in login_url.lower():
        return "jsonBasedAuthentication"
    return "formBasedAuthentication"


def _login_request_data(id_field: str, pw_field: str, *, json_body: bool) -> str:
    if json_body:
        return json.dumps({id_field: "{%username%}", pw_field: "{%password%}"}, separators=(",", ":"))
    return f"{id_field}={{%username%}}&{pw_field}={{%password%}}"


def setup_login_auth_context(
    zap: Any,
    *,
    context_name: str,
    login_url: str,
    id_field: str,
    pw_field: str,
    username: str,
    password: str,
    entry: dict[str, str],
) -> dict[str, Any]:
    """Create a ZAP context with login URL + credentials for rule 40023."""
    login_url = probe_url(login_url.rstrip("/"))
    parsed = urlparse(login_url)
    host_pattern = f"{parsed.scheme}://{re.escape(parsed.netloc)}.*"

    stats: dict[str, Any] = {"context_name": context_name, "login_url": login_url}
    try:
        zap.context.remove_context(context_name)
    except Exception:
        pass

    context_id = str(zap.context.new_context(context_name))
    stats["context_id"] = context_id
    zap.context.include_in_context(context_name, host_pattern)

    json_body = _auth_method_for_entry(entry, login_url) == "jsonBasedAuthentication"
    login_request_data = _login_request_data(id_field, pw_field, json_body=json_body)
    auth_methods = (
        ["jsonBasedAuthentication", "formBasedAuthentication"]
        if json_body
        else ["formBasedAuthentication"]
    )

    auth_config_base = (
        f"loginUrl={urllib.parse.quote(login_url, safe='')}"
        f"&loginRequestData={urllib.parse.quote(login_request_data, safe='')}"
    )
    auth_set = False
    last_error = ""
    for method in auth_methods:
        try:
            zap.authentication.set_authentication_method(context_id, method, auth_config_base)
            stats["auth_method"] = method
            auth_set = True
            break
        except Exception as exc:
            last_error = str(exc)
    if not auth_set:
        raise RuntimeError(last_error or "Failed to configure ZAP authentication")

    zap.sessionManagement.set_session_management_method(
        context_id,
        "cookieBasedSessionManagement",
        "",
    )
    try:
        zap.authentication.set_logged_in_indicator(context_id, "HTTP/1.1 2")
        zap.authentication.set_logged_out_indicator(context_id, "HTTP/1.1 4")
    except Exception:
        pass

    user_id = str(zap.users.new_user(context_id, username))
    creds = (
        f"username={urllib.parse.quote(username, safe='')}"
        f"&password={urllib.parse.quote(password, safe='')}"
    )
    zap.users.set_authentication_credentials(context_id, user_id, creds)
    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(context_id, "true")
    stats["user_id"] = user_id
    return stats


def _wait_for_ascan(zap: Any, scan_ids: list[str], *, max_seconds: int) -> dict[str, Any]:
    deadline = time.time() + max_seconds
    pending = len(scan_ids)
    while time.time() < deadline and pending > 0:
        pending = 0
        for sid in scan_ids:
            try:
                if int(zap.ascan.status(sid)) < 100:
                    pending += 1
            except Exception:
                continue
        if pending == 0:
            break
        time.sleep(2)
    return {"scan_ids": scan_ids, "pending": pending, "max_seconds": max_seconds}


def zap_alert_to_finding(
    alert: dict[str, Any],
    *,
    login_url: str,
    login_label: str,
) -> DiagnosisFinding | None:
    plugin_id = str(alert.get("pluginId", ""))
    if not is_username_enum_plugin(plugin_id):
        return None
    url = str(alert.get("url") or login_url)
    name = str(alert.get("alert") or alert.get("name") or PLUGIN_LABEL)
    other = str(alert.get("other") or alert.get("evidence") or "").strip()
    return DiagnosisFinding(
        severity="medium",
        message=f"[6-2] ZAP username enumeration at `{login_label}`: {name}",
        evidence={
            "rule_id": "6-2-login-enumeration",
            "source": "zap",
            "engine": "zap",
            "plugin_id": plugin_id,
            "login_url": login_url,
            "login_label": login_label,
            "url": url,
            "param": alert.get("param"),
            "risk": alert.get("risk"),
            "other_info": other or None,
            "trigger": f"zap_rule_{plugin_id}",
            "trigger_label": PLUGIN_LABEL,
            "remediation": (
                "Return the same generic login failure message and HTTP status "
                "for unknown user and wrong password (e.g. invalid credentials)"
            ),
        },
    )


def collect_username_enum_findings(
    zap: Any,
    login_entries: list[dict[str, str]],
) -> list[DiagnosisFinding]:
    findings: list[DiagnosisFinding] = []
    seen: set[str] = set()

    for entry in login_entries:
        login_url = probe_url(str(entry.get("url") or ""))
        label = str(entry.get("label") or login_url)
        try:
            alerts = zap.core.alerts(baseurl=login_url)
        except Exception:
            alerts = []
        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue
            finding = zap_alert_to_finding(alert, login_url=login_url, login_label=label)
            if finding is None:
                continue
            ev = finding.evidence or {}
            dedupe = f"{ev.get('plugin_id')}:{ev.get('url')}:{ev.get('param')}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.append(finding)
    return findings


def run_zap_enumeration_phase(
    raw_config: dict[str, Any],
    login_entries: list[dict[str, str]],
    *,
    auth_cfg: dict[str, Any],
    account_email: str,
    wrong_password: str,
    max_minutes: int = 5,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    scan_cfg = raw_config.get("diagnosis_6_2") or raw_config.get("scan_6_2") or {}
    if scan_cfg.get("zap_enabled") is False:
        return [], {"zap": "skipped", "reason": "zap_enabled=false"}

    zap_cfg = raw_config.get("zap") or {}
    proxy = ensure_zap_proxy(zap_cfg)
    api_key = str(zap_cfg.get("api_key") or "")
    zap = connect_zap(proxy, api_key)

    id_field = str(auth_cfg.get("id_field") or "email")
    pw_field = str(auth_cfg.get("pw_field") or "password")
    max_seconds = max(60, min(max_minutes * 60, 600))
    per_entry_seconds = max(30, max_seconds // max(1, len(login_entries)))

    stats: dict[str, Any] = {
        "zap_proxy": proxy,
        "plugin_id": USERNAME_ENUM_PLUGIN_ID,
        "entries": len(login_entries),
        "entry_results": [],
    }
    findings: list[DiagnosisFinding] = []

    try:
        stats["workspace_reset_before"] = reset_zap_workspace(zap, session_name="argus-g62-start")
        configure_username_enum_scanner(zap)

        for index, entry in enumerate(login_entries):
            login_url = probe_url(str(entry.get("url") or ""))
            label = str(entry.get("label") or login_url)
            context_name = f"argus-g62-{index}"
            entry_stats: dict[str, Any] = {"label": label, "login_url": login_url}

            try:
                entry_stats["context"] = setup_login_auth_context(
                    zap,
                    context_name=context_name,
                    login_url=login_url,
                    id_field=id_field,
                    pw_field=pw_field,
                    username=account_email,
                    password=wrong_password,
                    entry=entry,
                )
                context_id = entry_stats["context"]["context_id"]

                try:
                    zap.urlopen(login_url)
                except Exception:
                    pass

                scan_id = str(
                    zap.ascan.scan(
                        url=login_url,
                        recurse=False,
                        contextid=context_id,
                        scanpolicyname="",
                    )
                )
                wait_stats = _wait_for_ascan(zap, [scan_id], max_seconds=per_entry_seconds)
                entry_stats.update(wait_stats)
                entry_stats["scan_id"] = scan_id
            except Exception as exc:
                entry_stats["error"] = str(exc)[:300]
            finally:
                try:
                    zap.forcedUser.set_forced_user_mode_enabled(
                        entry_stats.get("context", {}).get("context_id", ""),
                        "false",
                    )
                except Exception:
                    pass
                try:
                    zap.context.remove_context(context_name)
                except Exception:
                    pass

            stats["entry_results"].append(entry_stats)

        findings = collect_username_enum_findings(zap, login_entries)
        stats["alerts"] = len(findings)
        stats["findings"] = len(findings)
    finally:
        try:
            stats["workspace_reset_after"] = reset_zap_workspace(zap, session_name="argus-g62-done")
        except Exception as exc:
            stats["workspace_reset_after"] = {"error": str(exc)}

    return findings, stats
