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
    judge = _load_local("upload_judge")
    findings: list[DiagnosisFinding] = []
    stats = {
        "cases_total": len(all_results),
        "vulnerable": 0,
        "safe": 0,
        "review": 0,
        "error": 0,
        "skipped": 0,
    }
    for result in all_results:
        stats[result.verdict] = stats.get(result.verdict, 0) + 1
        finding = judge.result_to_finding(result)
        if finding:
            findings.append(finding)
    return findings, stats


def run_g21_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    _ = module_dir
    raw = ctx.raw_config or {}
    opts = _scan_options(raw)

    if not opts.seller_email or not opts.seller_password.strip():
        return ScanResult(
            status="skipped",
            message="셀러 계정(이메일·비밀번호)이 필요합니다 — 진단 시작 시 입력하세요",
        )
    if opts.seller_id <= 0:
        return ScanResult(
            status="skipped",
            message="seller_id가 필요합니다 — Onde 판매자 ID를 입력하세요",
        )

    upload_context = _load_local("upload_context")
    upload_board = _load_local("upload_board")
    upload_seller = _load_local("upload_seller")

    total_steps = 3 + (2 if opts.user_email and opts.user_password.strip() else 0)
    prepare(total_steps, "2-1: 악성 파일 업로드 스캔 준비")
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

        user_ctx = None
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
        seller_ctx.client.close()
        if user_ctx is not None:
            user_ctx.client.close()

    findings, stats = _aggregate_results(all_results)
    stats["seller_email"] = opts.seller_email
    stats["seller_id"] = opts.seller_id
    stats["user_probed"] = bool(opts.user_email and opts.user_password.strip())

    vuln_count = stats.get("vulnerable", 0)
    if vuln_count:
        status = "fail"
        message = f"악성 파일 업로드 허용 {vuln_count}건 — 필터링 우회 가능"
    elif stats.get("review", 0):
        status = "review"
        message = "확인 필요 항목 있음 — 인증/엔드포인트 상태를 점검하세요"
    else:
        status = "pass"
        message = f"업로드 필터링 probe {stats.get('cases_total', 0)}건 — 취약 응답 없음"

    findings.insert(
        0,
        DiagnosisFinding(
            severity="info",
            message="2-1 upload scan statistics",
            evidence={"stats": stats},
        ),
    )
    return ScanResult(status=status, message=message, findings=findings, stats=stats)
