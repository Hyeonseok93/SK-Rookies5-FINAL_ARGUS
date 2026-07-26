"""3-2 인증 실패 횟수 제한 검사 오케스트레이션"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.auth_probe_service import configured_login_entries, valid_login_accounts
from app.services.test_accounts_service import load_test_accounts
from diagnosis.context import DiagnosisContext
from diagnosis.endpoint_auth_passes import load_login_report, pick_account_for_login_entry
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g32_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path}를 불러올 수 없습니다")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanOptions:
    timeout: float = 10.0
    max_attempts: int = 6
    interval_sec: float = 0.05
    wrong_password: str = "__ARGUS_INVALID_PASSWORD__"
    probe_account_email: str | None = None
    strict: bool = True
    max_login_entries: int = 0


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
        # 5회의 일반적인 실패 후 6번째 요청에서 잠금 신호가 나타날 수 있음
        max_attempts=max(6, min(int(cfg.get("max_attempts", 6)), 25)),
        interval_sec=max(0.0, min(float(cfg.get("interval_sec", 0.05)), 2.0)),
        wrong_password=str(cfg.get("wrong_password") or "__ARGUS_INVALID_PASSWORD__"),
        probe_account_email=str(cfg["probe_account_email"]).strip()
        if cfg.get("probe_account_email")
        else None,
        strict=bool(cfg.get("strict", True)),
        max_login_entries=max(0, min(int(cfg.get("max_login_entries", 0)), 50)),
    )


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
    if opts.max_login_entries > 0:
        entries = entries[: opts.max_login_entries]
    accounts = valid_login_accounts(load_test_accounts().get("accounts") or [])

    if not entries:
        return ScanResult(
            status="skipped",
            message=(
                "로그인 엔드포인트가 없습니다 — 인벤토리를 재생성(Build/Discover)하거나 "
                "대시보드 Login Endpoints에 로그인 API·페이지 URL을 추가하세요"
            ),
            stats={"login_entries": 0},
        )
    if not accounts:
        return ScanResult(
            status="skipped",
            message="테스트 계정이 없습니다 — 대시보드 Test Accounts에 전용 probe 계정을 추가하세요",
            stats={"login_entries": len(entries), "accounts": 0},
        )

    rules_mod = _load_local("lockout_rules")
    probes_mod = _load_local("probes")
    login_report = load_login_report(ctx.data_dir, ctx.raw_config)

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
        account = pick_account_for_login_entry(
            entry,
            accounts,
            login_report,
            override_email=opts.probe_account_email,
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
        message = "실행된 잠금 검사가 없습니다"
    elif combined_stats.get("errors", 0) == total_probed:
        status = "error"
        message = "모든 잠금 검사가 서버에 도달하지 못했습니다"
    elif status == "pass":
        message = (
            f"{total_probed}개 중 {total_limit}개 로그인 엔드포인트에서 인증 실패 제한 확인 "
            f"(각 {opts.max_attempts}회 시도 내에서 5회 실패 정책 점검)"
        )
    elif status == "fail":
        message = (
            f"{total_probed}개 중 {total_no_limit}개 로그인 엔드포인트에 인증 실패 제한 없음 "
            f"(5회 연속 실패 후에도 제한 없음; 각 {opts.max_attempts}회 시도)"
        )
    else:
        message = f"인증 실패 제한 검사: 로그인 엔드포인트 {total_probed}개"

    if total_limit and total_no_limit:
        message += f" — 혼재 (정상 {total_limit}개, 누락 {total_no_limit}개)"

    return ScanResult(findings=all_findings, stats=combined_stats, status=status, message=message)
