"""Orchestrate guideline 6-2 login failure uniformity scan."""

from __future__ import annotations

import importlib.util
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.auth_probe_service import (
    configured_login_entries,
    valid_login_accounts,
)
from app.services.test_accounts_service import load_test_accounts
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding

from app.services.zap_util import ZapNotAvailableError


_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g62_{name}"
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
    strict: bool = True
    wrong_password: str = "__ARGUS_INVALID_PASSWORD__"
    probe_account_email: str | None = None
    zap_enabled: bool = True
    zap_max_minutes: int = 5


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "pass"
    message: str = ""


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_6_2") or raw.get("scan_6_2") or {}
    return ScanOptions(
        timeout=float(cfg.get("timeout", 10.0)),
        strict=bool(cfg.get("strict", True)),
        wrong_password=str(cfg.get("wrong_password") or "__ARGUS_INVALID_PASSWORD__"),
        probe_account_email=str(cfg["probe_account_email"]).strip()
        if cfg.get("probe_account_email")
        else None,
        zap_enabled=bool(cfg.get("zap_enabled", True)),
        zap_max_minutes=max(1, min(int(cfg.get("zap_max_minutes", 5)), 30)),
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


def run_g62_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    opts = _scan_options(ctx.raw_config)
    auth_cfg = ctx.raw_config.get("auth") or {}

    entries = configured_login_entries()
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
            message="No test accounts — add accounts in dashboard Test Accounts",
            stats={"login_entries": len(entries), "accounts": 0},
        )

    rules_mod = _load_local("login_rules")
    probes_mod = _load_local("probes")

    from diagnosis.progress_reporter import prepare, step_progress, zap_phase

    prepare(len(entries), f"6-2: {len(entries)} login entry(ies)")
    report_step = step_progress(total=len(entries), phase_name="httpx", label="login enum")

    fake_email = f"argus-probe-{uuid.uuid4().hex[:12]}@invalid.example"
    all_findings: list[DiagnosisFinding] = []
    combined_stats: dict[str, Any] = {
        "login_entries": len(entries),
        "accounts_available": len(accounts),
        "strict": opts.strict,
        "errors": 0,
    }
    total_probed = 0
    total_uniform = 0
    total_risk = 0
    entry_idx = 0

    for entry in entries:
        account = _pick_account(
            entry,
            accounts=accounts,
            override=opts.probe_account_email,
        )
        if not account or not str(account.get("password", "")).strip():
            continue

        findings, stats = probes_mod.run_login_enumeration_probes(
            [entry],
            auth_cfg=auth_cfg,
            account_email=str(account["email"]),
            account_password=str(account["password"]),
            snapshot_fn=rules_mod.snapshot_from_http,
            compare_set_fn=rules_mod.compare_login_snapshot_set,
            fake_email=fake_email,
            wrong_password=opts.wrong_password,
            timeout=opts.timeout,
            strict=opts.strict,
        )
        all_findings.extend(findings)
        total_probed += stats.get("probed", 0)
        total_uniform += stats.get("uniform", 0)
        total_risk += stats.get("enumeration_risk", 0)
        combined_stats["errors"] = combined_stats.get("errors", 0) + stats.get("errors", 0)
        combined_stats[f"entry:{entry.get('label', entry['url'])}"] = stats
        entry_idx += 1
        report_step(entry_idx, str(entry.get("label") or entry.get("url") or ""))

    combined_stats.update(
        {
            "probed": total_probed,
            "uniform": total_uniform,
            "enumeration_risk": total_risk,
            "fake_email": fake_email,
            "httpx_findings": len(all_findings),
        }
    )

    zap_ran = False
    if opts.zap_enabled and entries:
        primary = _pick_account(
            entries[0],
            accounts=accounts,
            override=opts.probe_account_email,
        )
        if primary:
            try:
                zap_phase("ZAP 6-2 enumeration scan…")
                zap_mod = _load_local("zap_scan")
                zap_findings, zap_stats = zap_mod.run_zap_enumeration_phase(
                    ctx.raw_config,
                    entries,
                    auth_cfg=auth_cfg,
                    account_email=str(primary["email"]),
                    wrong_password=opts.wrong_password,
                    max_minutes=opts.zap_max_minutes,
                )
                all_findings.extend(zap_findings)
                combined_stats["zap"] = zap_stats
                combined_stats["zap_findings"] = len(zap_findings)
                zap_ran = True
            except ZapNotAvailableError as exc:
                combined_stats["zap"] = {"error": str(exc)}
            except Exception as exc:
                combined_stats["zap"] = {"error": str(exc)[:300]}

    if not zap_ran and opts.zap_enabled:
        combined_stats.setdefault("zap", {"error": "ZAP phase did not run"})

    status = _overall_status(all_findings)
    if total_probed == 0:
        status = "skipped"
        message = "No login probes executed"
    elif combined_stats.get("errors", 0) == total_probed:
        status = "error"
        message = "All login probes unreachable"
    elif status == "pass":
        message = (
            f"Uniform login failure on {total_probed} login entry(s) — "
            "A/B/C failure responses match"
        )
    elif status == "fail":
        parts = []
        if total_risk > 0:
            parts.append(f"httpx enumeration {total_risk}/{total_probed}")
        zap_fail = combined_stats.get("zap_findings", 0)
        if isinstance(zap_fail, int) and zap_fail > 0:
            parts.append(f"ZAP 40023 alerts {zap_fail}")
        detail = " · ".join(parts) if parts else "failure responses differ"
        message = f"Account enumeration risk ({detail})"
    else:
        message = f"Login enumeration scan: {total_probed} entry(s)"

    return ScanResult(findings=all_findings, stats=combined_stats, status=status, message=message)
