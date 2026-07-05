"""Orchestrate guideline 4-2 auth token safety scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g42_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 10.0
    max_token_lifetime_sec: int = 1800
    min_token_length: int = 32
    min_entropy: float = 3.5
    probe_path: str = "/api/v1/members/me"
    probe_account_email: str | None = None
    relogin_enabled: bool = True
    duplicate_login_enabled: bool = True
    duplicate_login_ip_enabled: bool = True
    probe_client_ips: list[str] = field(
        default_factory=lambda: ["203.0.113.10", "198.51.100.20"]
    )
    logout_enabled: bool = True
    client_logout_enabled: bool = True
    refresh_path: str | None = None
    no_server_logout_finding: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_4_2") or raw.get("scan_4_2") or {}
    max_min = int(cfg.get("max_token_lifetime_minutes", 30))
    return ScanOptions(
        timeout=float(cfg.get("timeout", 10.0)),
        max_token_lifetime_sec=max(300, min(max_min * 60, 86400)),
        min_token_length=max(8, min(int(cfg.get("min_token_length", 32)), 256)),
        min_entropy=max(2.0, min(float(cfg.get("min_entropy", 3.5)), 6.0)),
        probe_path=str(cfg.get("probe_path", "/api/v1/members/me")).strip() or "/api/v1/members/me",
        probe_account_email=str(cfg["probe_account_email"]).strip()
        if cfg.get("probe_account_email")
        else None,
        relogin_enabled=bool(cfg.get("relogin_enabled", True)),
        duplicate_login_enabled=bool(cfg.get("duplicate_login_enabled", True)),
        duplicate_login_ip_enabled=bool(cfg.get("duplicate_login_ip_enabled", True)),
        probe_client_ips=[
            str(ip).strip()
            for ip in (cfg.get("probe_client_ips") or ["203.0.113.10", "198.51.100.20"])
            if str(ip).strip()
        ]
        or ["203.0.113.10", "198.51.100.20"],
        logout_enabled=bool(cfg.get("logout_enabled", True)),
        client_logout_enabled=bool(cfg.get("client_logout_enabled", True)),
        refresh_path=(
            str(cfg["refresh_path"]).strip()
            if cfg.get("refresh_path")
            else None
        ),
        no_server_logout_finding=bool(cfg.get("no_server_logout_finding", True)),
    )


def _dedupe_findings(items: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[DiagnosisFinding] = []
    for item in items:
        rule = str((item.evidence or {}).get("rule_id") or "")
        email = str((item.evidence or {}).get("email") or "")
        key = (rule, email)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _status_from_findings(findings: list[DiagnosisFinding]) -> tuple[str, str]:
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    if high:
        return "fail", f"4-2 token safety: {high} high finding(s)"
    if medium:
        return "warn", f"4-2 token safety: {medium} medium finding(s)"
    return "pass", "4-2 token/session safety checks passed"


def run_g42_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)
    targets = _load_local("targets")
    token_mod = _load_local("token_analyzer")
    lifecycle = _load_local("lifecycle_probes")

    login_report = None
    if ctx.data_dir:
        login_report = targets.load_login_report(ctx.data_dir, raw)

    accounts = targets.pick_test_accounts()
    sessions, auth_meta = targets.load_sessions(raw, ctx.data_dir)

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "sessions": len(sessions),
        "auth_source": auth_meta.get("source"),
        "probe_path": opts.probe_path,
    }

    if login_report:
        stats["login_matrix_accounts"] = len(login_report.get("accounts") or [])
        stats["login_entries"] = len(login_report.get("login_entries") or [])

    if not sessions:
        msg = "No test-account login sessions — configure Test Accounts and run Verify"
        if login_report and int(login_report.get("session_count") or 0) == 0:
            msg = (
                "Verify login failed for all test accounts (session_count=0) — "
                "fix credentials on dashboard Base URLs, then re-run Verify"
            )
        return ScanResult(
            status="skipped",
            message=msg,
            stats=stats,
            findings=findings,
        )

    account, session = targets.pick_probe_account(
        sessions,
        accounts,
        login_report,
        raw_config=raw,
        override_email=opts.probe_account_email,
        probe_path=opts.probe_path,
    )
    login_url = None
    if account:
        login_url = targets.resolve_login_url_for_account(account, session, raw, login_report)
        stats["probe_account"] = account.get("email")
        stats["probe_login_url"] = login_url

    from diagnosis.progress_reporter import prepare, step_progress

    lifecycle_steps = 1
    if account and login_url:
        if opts.relogin_enabled:
            lifecycle_steps += 1
        if opts.duplicate_login_enabled:
            lifecycle_steps += 1
        if opts.duplicate_login_ip_enabled:
            lifecycle_steps += 1
        if opts.logout_enabled:
            lifecycle_steps += 1
        if opts.logout_enabled and opts.client_logout_enabled:
            lifecycle_steps += 1
    prepare(lifecycle_steps, f"4-2: {lifecycle_steps} lifecycle check(s)")
    report_step = step_progress(total=lifecycle_steps, phase_name="httpx", label="4-2")
    step_n = 0

    step_n += 1
    report_step(step_n, "token analysis")
    tf, tstats = token_mod.analyze_sessions_tokens(
        sessions,
        max_lifetime_sec=opts.max_token_lifetime_sec,
        min_token_length=opts.min_token_length,
        min_entropy=opts.min_entropy,
    )
    findings.extend(tf)
    stats["token_analysis"] = tstats

    auth_cfg = raw.get("auth") or {}
    lifecycle_stats: dict[str, Any] = {}

    if account and login_url:
        base_url = targets.resolve_probe_base(session, login_url, raw)
        stats["probe_base_url"] = base_url

        if opts.relogin_enabled:
            step_n += 1
            report_step(step_n, "relogin uniqueness")
            finding, relogin_stats = lifecycle.probe_relogin_token_uniqueness(
                auth_cfg,
                account,
                login_url,
                timeout=opts.timeout,
            )
            lifecycle_stats["relogin"] = relogin_stats
            if finding:
                findings.append(finding)

        if opts.duplicate_login_enabled and base_url:
            step_n += 1
            report_step(step_n, "duplicate login")
            finding, dup_stats = lifecycle.probe_duplicate_login(
                auth_cfg,
                account,
                login_url,
                base_url=base_url,
                probe_path=opts.probe_path,
                timeout=opts.timeout,
            )
            lifecycle_stats["duplicate_login"] = dup_stats
            if finding:
                findings.append(finding)

        if opts.duplicate_login_ip_enabled and base_url:
            step_n += 1
            report_step(step_n, "cross-IP duplicate login")
            ip_findings, ip_stats = lifecycle.probe_duplicate_login_cross_ip(
                auth_cfg,
                account,
                login_url,
                base_url=base_url,
                probe_path=opts.probe_path,
                timeout=opts.timeout,
                client_ips=opts.probe_client_ips,
            )
            lifecycle_stats["duplicate_login_cross_ip"] = ip_stats
            findings.extend(ip_findings)
            stats["duplicate_login_ip_findings"] = len(ip_findings)

        logout_urls = targets.discover_logout_urls(raw, data_dir=ctx.data_dir)
        stats["logout_urls"] = logout_urls
        if opts.logout_enabled and logout_urls and base_url:
            step_n += 1
            report_step(step_n, "server logout invalidation")
            logout_findings = 0
            for logout_url in logout_urls[:3]:
                finding, lo_stats = lifecycle.probe_logout_invalidation(
                    auth_cfg,
                    account,
                    login_url,
                    logout_url,
                    base_url=base_url,
                    probe_path=opts.probe_path,
                    timeout=opts.timeout,
                )
                lifecycle_stats[f"logout:{logout_url}"] = lo_stats
                if finding:
                    findings.append(finding)
                    logout_findings += 1
            stats["logout_probes"] = logout_findings
        elif opts.logout_enabled and opts.client_logout_enabled and base_url:
            step_n += 1
            report_step(step_n, "client-only logout")
            gap = targets.inventory_auth_logout_gap(
                raw, data_dir=ctx.data_dir, logout_urls=logout_urls
            )
            if gap:
                stats["auth_logout_gap"] = gap
                if opts.no_server_logout_finding:
                    findings.append(
                        targets.no_server_logout_finding(
                            gap,
                            email=str(account.get("email") or ""),
                            login_url=login_url,
                        )
                    )
            refresh_path = opts.refresh_path
            if not refresh_path:
                refresh_path = targets.resolve_refresh_path_for_base(
                    raw,
                    base_url=base_url,
                    data_dir=ctx.data_dir,
                )
            stats["refresh_path"] = refresh_path
            stats["refresh_paths_inventory"] = targets.discover_refresh_paths(
                raw, data_dir=ctx.data_dir
            )
            client_findings, client_stats = lifecycle.probe_client_only_logout(
                auth_cfg,
                account,
                login_url,
                base_url=base_url,
                probe_path=opts.probe_path,
                refresh_path=refresh_path,
                timeout=opts.timeout,
            )
            lifecycle_stats["client_logout"] = client_stats
            findings.extend(client_findings)
            stats["client_logout_findings"] = len(client_findings)
        elif opts.logout_enabled:
            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message=(
                        "[4-2] Logout tests skipped — no logout URL and "
                        "client_logout_enabled=false"
                    ),
                    evidence={
                        "rule_id": "4-2-logout-skipped",
                        "reason": (
                            "configure diagnosis_4_2.logout_urls, enable client_logout_enabled, "
                            "or add logout API to api-tree"
                        ),
                        "remediation": (
                            "Enable diagnosis_4_2.client_logout_enabled for SPA client-only logout"
                        ),
                    },
                )
            )
    else:
        stats["lifecycle_skipped"] = "no_probe_account_or_login_url"

    stats["lifecycle"] = lifecycle_stats
    findings = _dedupe_findings(findings)
    stats["findings"] = len(findings)
    stats["by_severity"] = {
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "info": sum(1 for f in findings if f.severity == "info"),
    }

    status, message = _status_from_findings(
        [f for f in findings if (f.evidence or {}).get("rule_id") != "4-2-logout-skipped"]
    )
    return ScanResult(status=status, message=message, stats=stats, findings=findings)
