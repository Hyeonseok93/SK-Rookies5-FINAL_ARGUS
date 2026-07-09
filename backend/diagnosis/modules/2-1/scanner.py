"""Orchestrate 2-1 malicious file upload scan."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext
from diagnosis.progress_reporter import phase, prepare
from diagnosis.result import DiagnosisFinding

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    mod_name = f"diag_g21_{name}"
    path = _MODULE_DIR / f"{name}.py"
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
    seller_email: str = ""
    seller_password: str = ""
    seller_id: int = 0
    user_email: str = ""
    user_password: str = ""
    timeout: float = 10.0


@dataclass
class ScanResult:
    status: str
    message: str
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def _scan_options(raw: dict[str, Any]) -> ScanOptions:
    cfg = raw.get("diagnosis_2_1") or {}
    try:
        seller_id = int(cfg.get("seller_id") or 0)
    except (TypeError, ValueError):
        seller_id = 0
    try:
        timeout = float(cfg.get("timeout") or 10.0)
    except (TypeError, ValueError):
        timeout = 10.0
    return ScanOptions(
        seller_email=str(cfg.get("seller_email") or "").strip(),
        seller_password=str(cfg.get("seller_password") or ""),
        seller_id=seller_id,
        user_email=str(cfg.get("user_email") or "").strip(),
        user_password=str(cfg.get("user_password") or ""),
        timeout=max(3.0, min(timeout, 60.0)),
    )


def _aggregate_results(all_results: list) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    모든 probe 결과를 findings로 변환하고 정탐/오탐/수동검토 통계를 집계합니다.

    verdict 매핑:
      vulnerable     → 정탐 (true_positive) → severity=high
      false_positive → 오탐 (false_positive) → severity=low
      review         → 수동검토              → severity=medium
      safe / skipped → finding 생성 안 함
      error          → severity=low
    """
    judge = _load_local("upload_judge")
    findings: list[DiagnosisFinding] = []
    by_verdict: dict[str, int] = {
        "true_positive": 0,
        "false_positive": 0,
        "review": 0,
        "safe": 0,
        "error": 0,
        "skipped": 0,
    }

    for result in all_results:
        v = getattr(result, "verdict", None)
        if v == "vulnerable":
            by_verdict["true_positive"] += 1
        elif v == "false_positive":
            by_verdict["false_positive"] += 1
        elif v in by_verdict:
            by_verdict[v] += 1

        finding = judge.result_to_finding(result)
        if finding:
            findings.append(finding)

    by_severity = {
        sev: sum(1 for f in findings if f.severity == sev)
        for sev in ("high", "medium", "low", "info")
    }

    stats: dict[str, Any] = {
        "cases_total": len(all_results),
        "by_verdict": by_verdict,
        "by_severity": by_severity,
    }
    return findings, stats


# ── 하위 호환: run_scan 별칭 (기존 호출부 대응) ─────────────────────────────
def run_scan(ctx: DiagnosisContext) -> ScanResult:
    return run_g21_scan(ctx, _MODULE_DIR)


def run_g21_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)

    # ── 계정 fallback 처리 ────────────────────────────────────────────────────
    if not opts.seller_email or not opts.seller_password.strip():
        # diagnosis_service._build_overrides 가 "diagnosis_2_1" 키로 주입
        g21_cfg = raw.get("diagnosis_2_1") or raw.get("g21") or {}
        opts.seller_email = str(g21_cfg.get("seller_email") or "").strip()
        opts.seller_password = str(g21_cfg.get("seller_password") or "")
        opts.seller_id = int(g21_cfg.get("seller_id") or 0)
        opts.user_email = str(g21_cfg.get("user_email") or "").strip()
        opts.user_password = str(g21_cfg.get("user_password") or "")

    if not opts.seller_email or not opts.seller_password.strip():
        # Onde 기본 계정 fallback
        print("[2-1] WARNING: no accounts configured — using Onde fallback credentials")
        opts.seller_email = "airluna@travel.com"
        opts.seller_password = "password"
        opts.seller_id = 11
        opts.user_email = "yerin@travel.com"
        opts.user_password = "password"

    upload_context = _load_local("upload_context")
    upload_board = _load_local("upload_board")
    upload_seller = _load_local("upload_seller")

    total_steps = 3 + (2 if opts.user_email and opts.user_password.strip() else 0)
    prepare(total_steps, "2-1: 악성 파일 업로드 스캔")
    all_results: list = []
    step = 0
    user_ctx = None

    try:
        phase("셀러 계정 로그인…", done=step, total=total_steps)
        seller_ctx = upload_context.build_probe_context(
            raw,
            email=opts.seller_email,
            password=opts.seller_password,
            seller_id=opts.seller_id,
            timeout=opts.timeout,
            label="seller",
        )
    except Exception as exc:
        return ScanResult(
            status="error",
            message=f"셀러 로그인 실패: {exc}",
        )

    try:
        step += 1
        phase("숙소 썸네일 업로드 probe…", done=step, total=total_steps)
        all_results.extend(upload_seller.run_accommodation_probes(seller_ctx))

        step += 1
        phase("렌터카 썸네일 업로드 probe…", done=step, total=total_steps)
        all_results.extend(upload_seller.run_car_probes(seller_ctx))

        upload_dashboard = _load_local("upload_dashboard")
        dashboard_rows = upload_dashboard.run_dashboard_upload_probes(seller_ctx, raw)
        if dashboard_rows:
            step += 1
            total_steps += 1
            phase("대시보드 업로드 엔드포인트 probe…", done=step, total=total_steps)
            all_results.extend(dashboard_rows)

        if opts.user_email and opts.user_password.strip():
            try:
                step += 1
                phase("일반 계정 로그인 (게시판)…", done=step, total=total_steps)
                user_ctx = upload_context.build_probe_context(
                    raw,
                    email=opts.user_email,
                    password=opts.user_password,
                    seller_id=0,
                    timeout=opts.timeout,
                    label="user",
                )
            except Exception as exc:
                all_results.append(
                    _load_local("upload_judge").UploadCaseResult(
                        suite="board",
                        method="POST",
                        endpoint="/api/v1/posts",
                        filename="—",
                        attack_desc="user login",
                        status_code=0,
                        verdict="review",
                        detail=f"일반 계정 로그인 실패: {exc}",
                    )
                )

        if user_ctx is not None:
            step += 1
            phase("게시판 POST 업로드 probe…", done=step, total=total_steps)
            all_results.extend(upload_board.run_board_post_probes(user_ctx))
            step += 1
            phase("게시판 PUT 업로드 probe…", done=step, total=total_steps)
            all_results.extend(upload_board.run_board_edit_probes(user_ctx))
    finally:
        try:
            seller_ctx.client.close()
        except Exception:
            pass
        if user_ctx is not None:
            try:
                user_ctx.client.close()
            except Exception:
                pass

    findings, stats = _aggregate_results(all_results)
    stats["seller_email"] = opts.seller_email
    stats["seller_id"] = opts.seller_id
    stats["user_probed"] = bool(opts.user_email and opts.user_password.strip())
    stats["dashboard_upload_probes"] = sum(
        1 for r in all_results if getattr(r, "suite", "") == "dashboard_upload"
    )

    by_verdict = stats["by_verdict"]
    by_severity = stats["by_severity"]
    high_count = by_severity.get("high", 0)
    medium_count = by_severity.get("medium", 0)

    if high_count:
        final_status = "fail"
        final_msg = (
            f"[2-1] 취약: {high_count}건 정탐 "
            f"(오탐 {by_verdict['false_positive']}건, 수동검토 {by_verdict['review']}건) "
            f"/ {stats['cases_total']}개 프로브"
        )
    elif medium_count:
        final_status = "warn"
        final_msg = (
            f"[2-1] 수동검토 필요: {medium_count}건 "
            f"(정탐 0건, 오탐 {by_verdict['false_positive']}건) "
            f"/ {stats['cases_total']}개 프로브"
        )
    else:
        final_status = "pass"
        final_msg = (
            f"[2-1] 취약점 없음 "
            f"(오탐 {by_verdict['false_positive']}건 포함) "
            f"/ {stats['cases_total']}개 프로브"
        )

    # stats info finding (UI 통계 탭용)
    findings.insert(
        0,
        DiagnosisFinding(
            severity="info",
            message="2-1 upload scan statistics",
            evidence={"stats": stats},
        ),
    )
    return ScanResult(status=final_status, message=final_msg, findings=findings, stats=stats)
