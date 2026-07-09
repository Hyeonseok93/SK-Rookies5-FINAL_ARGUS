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
    user_email: str = ""
    user_password: str = ""
    admin_email: str = ""
    admin_password: str = ""
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
        timeout = float(cfg.get("timeout") or 10.0)
    except (TypeError, ValueError):
        timeout = 10.0
    return ScanOptions(
        seller_email=str(cfg.get("seller_email") or "").strip(),
        seller_password=str(cfg.get("seller_password") or ""),
        user_email=str(cfg.get("user_email") or "").strip(),
        user_password=str(cfg.get("user_password") or ""),
        admin_email=str(cfg.get("admin_email") or "").strip(),
        admin_password=str(cfg.get("admin_password") or ""),
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
        return ScanResult(
            status="skipped",
            message="셀러 계정(이메일·비밀번호)이 필요합니다 — 진단 시작 시 입력하세요",
        )

    upload_board = _load_local("upload_board")
    upload_seller = _load_local("upload_seller")

    import httpx

    api_base_url = "http://host.docker.internal:8080"
    for item in raw.get("api_tree", []):
        bu = str(item.get("base_url") or "")
        if bu and "8080" in bu:
            api_base_url = bu.rstrip("/")
            break

    def _login(email: str, password: str, is_seller: bool) -> dict[str, str]:
        if not email or not password.strip():
            return {}
        try:
            url = f"{api_base_url}/api/v1/auth/login"
            resp = httpx.post(url, json={"email": email, "password": password}, timeout=opts.timeout, verify=False)
            if resp.status_code == 200:
                body = resp.json()
                token = body.get("data", {}).get("accessToken", "") if isinstance(body.get("data"), dict) else body.get("accessToken", "")
                return {"Authorization": f"Bearer {token}"} if token else {}
            return {}
        except Exception:
            return {}

    zap_cfg = raw.get("zap") or {}
    total_steps = 3
    if opts.admin_email and opts.admin_password.strip():
        total_steps += 2
    if opts.user_email and opts.user_password.strip():
        total_steps += 3
    if zap_cfg:
        total_steps += 1

    prepare(total_steps, "2-1: 악성 파일 업로드 스캔")
    all_results: list = []
    step = 0

    phase("셀러 계정 로그인…", done=step, total=total_steps)
    seller_auth = _login(opts.seller_email, opts.seller_password, is_seller=True)
    if not seller_auth:
        return ScanResult(
            status="error",
            message=f"셀러 로그인 실패 (시도한 계정: '{opts.seller_email}'): 유효하지 않은 자격증명이거나 서버에 연결할 수 없습니다.",
        )

    try:
        step += 1
        phase("숙소 썸네일 업로드 probe…", done=step, total=total_steps)
        all_results.extend(upload_seller.run_accommodation_probes(api_base_url, 11, seller_auth, opts.timeout))

        step += 1
        phase("렌터카 썸네일 업로드 probe…", done=step, total=total_steps)
        all_results.extend(upload_seller.run_car_probes(api_base_url, 11, seller_auth, opts.timeout))

        if opts.admin_email and opts.admin_password.strip():
            step += 1
            phase("관리자 계정 로그인 (대시보드)…", done=step, total=total_steps)
            admin_auth = _login(opts.admin_email, opts.admin_password, is_seller=False)
            if not admin_auth:
                all_results.append(
                    _load_local("upload_judge").UploadCaseResult(
                        suite="dashboard_upload",
                        method="POST",
                        endpoint="—",
                        filename="—",
                        attack_desc="admin login",
                        status_code=0,
                        verdict="review",
                        detail=f"관리자 계정 로그인 실패",
                    )
                )
            else:
                upload_dashboard = _load_local("upload_dashboard")
                dashboard_rows = upload_dashboard.run_dashboard_upload_probes(api_base_url, admin_auth, opts.timeout, raw)
                if dashboard_rows:
                    step += 1
                    phase("대시보드 업로드 엔드포인트 probe…", done=step, total=total_steps)
                    all_results.extend(dashboard_rows)

        if opts.user_email and opts.user_password.strip():
            step += 1
            phase("일반 계정 로그인 (게시판)…", done=step, total=total_steps)
            user_auth = _login(opts.user_email, opts.user_password, is_seller=False)
            if not user_auth:
                all_results.append(
                    _load_local("upload_judge").UploadCaseResult(
                        suite="board",
                        method="POST",
                        endpoint="/api/v1/posts",
                        filename="—",
                        attack_desc="user login",
                        status_code=0,
                        verdict="review",
                        detail=f"일반 계정 로그인 실패",
                    )
                )
            else:
                step += 1
                phase("게시판 POST 업로드 probe…", done=step, total=total_steps)
                all_results.extend(upload_board.run_board_post_probes(api_base_url, user_auth, opts.timeout))
                step += 1
                phase("게시판 PUT 업로드 probe…", done=step, total=total_steps)
                all_results.extend(upload_board.run_board_edit_probes(api_base_url, user_auth, opts.timeout))
    finally:
        pass

    findings, stats = _aggregate_results(all_results)
    stats["seller_email"] = opts.seller_email
    stats["user_probed"] = bool(opts.user_email and opts.user_password.strip())
    stats["dashboard_upload_probes"] = sum(
        1 for r in all_results if getattr(r, "suite", "") == "dashboard_upload"
    )

    # ── ZAP 연동 스캔 (Seller 권한 기준) ───────────────────────────────────────
    if zap_cfg and seller_auth:
        step += 1
        phase("ZAP 프록시 기반 업로드 스캔 (Active Scan)…", done=step, total=total_steps)
        try:
            zap_scan = _load_local("zap_scan")
            zap_findings, zap_stats = zap_scan.run_zap_upload_phase(
                raw_config=raw,
                data_dir=ctx.data_dir,
                session_headers=seller_auth,
                max_minutes=15,
            )
            # ZAP 알림(Findings) 병합
            for f in zap_findings:
                # Map g21_models.DetectionResult to DiagnosisFinding
                sev = "info"
                risk = getattr(f, "risk", "").lower()
                if "high" in risk:
                    sev = "high"
                elif "medium" in risk:
                    sev = "medium"
                elif "low" in risk:
                    sev = "low"
                
                finding = DiagnosisFinding(
                    severity=sev,
                    message=f"[ZAP] {getattr(f, 'plugin_name', 'Unknown Vulnerability')}",
                    evidence={
                        "url": getattr(f, "url", ""),
                        "param": getattr(f, "param", ""),
                        "evidence": getattr(f, "evidence", ""),
                        "description": getattr(f, "description", ""),
                    }
                )
                findings.append(finding)
            
            # ZAP 통계 기록
            stats["zap_alerts"] = zap_stats.get("zap_alerts", 0)
            if "error" in zap_stats:
                stats["zap_error"] = zap_stats["error"]
        except Exception as exc:
            print(f"[2-1] ZAP Scan Error: {exc}")
            stats["zap_error"] = str(exc)

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
