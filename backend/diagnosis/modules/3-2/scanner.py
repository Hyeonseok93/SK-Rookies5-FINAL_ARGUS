"""Orchestrate guideline 3-2 auth failure count limit scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.auth_probe_service import configured_login_entries, valid_login_accounts
from app.services.test_accounts_service import load_test_accounts
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g32_{name}"
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
    max_attempts: int = 12
    interval_sec: float = 0.05
    wrong_password: str = "__ARGUS_INVALID_PASSWORD__"
    probe_account_email: str | None = None
    strict: bool = True


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_3_2") or raw.get("scan_3_2") or {}
    return ScanOptions(
        timeout=float(cfg.get("timeout", 10.0)),
        max_attempts=max(3, min(int(cfg.get("max_attempts", 12)), 25)),
        interval_sec=max(0.0, min(float(cfg.get("interval_sec", 0.05)), 2.0)),
        wrong_password=str(cfg.get("wrong_password") or "__ARGUS_INVALID_PASSWORD__"),
        probe_account_email=str(cfg["probe_account_email"]).strip()
        if cfg.get("probe_account_email")
        else None,
        strict=bool(cfg.get("strict", True)),
    )


def _pick_account(
    entry: dict[str, str],
    *,
    accounts: list[dict[str, str]],
    override: str | None,
) -> dict[str, str] | None:
    if override:
        for account in accounts:
            if account.get("email") == override:
                return account
        return None

    label = str(entry.get("label") or "").lower()
    path = entry.get("url", "").lower()
    if "admin" in label or "admin" in path:
        for account in accounts:
            if "admin" in account.get("email", "").lower():
                return account

    return accounts[0] if accounts else None


def _overall_status(findings: list[DiagnosisFinding]) -> str:
    if any(f.severity in ("high", "medium") for f in findings):
        return "fail"
    if any(f.severity == "low" for f in findings):
        return "warn"
    return "pass"


def run_g32_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    opts = _scan_options(ctx.raw_config)
    auth_cfg = ctx.raw_config.get("auth") or {}

    entries = configured_login_entries(auth_cfg)
    accounts = valid_login_accounts(load_test_accounts().get("accounts") or [])

    if not entries:
        return ScanResult(
            status="skipped",
            message=(
                "No login endpoints — rebuild inventory (Build/Discover) and/or add login API "
                "or page URLs under Dashboard Login Endpoints"
            ),
            stats={"login_entries": 0},
        )
    if not accounts:
        return ScanResult(
            status="skipped",
            message="No test accounts — add a dedicated probe account in dashboard Test Accounts",
            stats={"login_entries": len(entries), "accounts": 0},
        )

    rules_mod = _load_local("lockout_rules")
    probes_mod = _load_local("probes")

    from diagnosis.progress_reporter import prepare, step_progress

    prepare(len(entries), f"3-2: {len(entries)} login entry(ies)")
    report_step = step_progress(total=len(entries), phase_name="httpx", label="lockout")

    all_findings: list[DiagnosisFinding] = []
    combined_stats: dict[str, Any] = {
        "login_entries": len(entries),
        "accounts_available": len(accounts),
        "max_attempts": opts.max_attempts,
        "strict": opts.strict,
        "errors": 0,
    }
    total_probed = 0
    total_limit = 0
    total_no_limit = 0
    entry_idx = 0

    for entry in entries:
        account = _pick_account(
            entry,
            accounts=accounts,
            override=opts.probe_account_email,
        )
        if not account:
            continue

        findings, stats = probes_mod.run_lockout_probes(
            [entry],
            auth_cfg=auth_cfg,
            account_email=str(account["email"]),
            wrong_password=opts.wrong_password,
            max_attempts=opts.max_attempts,
            interval_sec=opts.interval_sec,
            snapshot_fn=rules_mod.snapshot_from_http,
            analyze_fn=rules_mod.analyze_lockout_sequence,
            timeout=opts.timeout,
            strict=opts.strict,
        )
        all_findings.extend(findings)
        total_probed += stats.get("probed", 0)
        total_limit += stats.get("limit_detected", 0)
        total_no_limit += stats.get("no_limit", 0)
        combined_stats["errors"] = combined_stats.get("errors", 0) + stats.get("errors", 0)
        combined_stats[f"entry:{entry.get('label', entry['url'])}"] = stats
        entry_idx += 1
        report_step(entry_idx, str(entry.get("label") or entry.get("url") or ""))

    combined_stats.update(
        {
            "probed": total_probed,
            "limit_detected": total_limit,
            "no_limit": total_no_limit,
            "httpx_findings": len(all_findings),
        }
    )

    status = _overall_status(all_findings)
    if total_probed == 0:
        status = "skipped"
        message = "No lockout probes executed"
    elif combined_stats.get("errors", 0) == total_probed:
        status = "error"
        message = "All lockout probes unreachable"
    elif status == "pass":
        message = (
            f"Auth failure limit present on {total_limit}/{total_probed} login entry(s) "
            f"({opts.max_attempts} attempts each)"
        )
    elif status == "fail":
        message = (
            f"Missing auth failure limit on {total_no_limit}/{total_probed} login entry(s) "
            f"({opts.max_attempts} wrong-password attempts)"
        )
    else:
        message = f"Auth failure limit scan: {total_probed} login entry(s)"

    if total_limit and total_no_limit:
        message += f" — mixed ({total_limit} ok, {total_no_limit} missing)"

    return ScanResult(findings=all_findings, stats=combined_stats, status=status, message=message)
