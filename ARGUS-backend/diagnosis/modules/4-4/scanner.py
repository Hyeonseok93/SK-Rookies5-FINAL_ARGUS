"""4-4 능동 진단 오케스트레이션"""

from __future__ import annotations

import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diagnosis.auth_session_pool import DiagnosisAuthPool
from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir
from diagnosis.progress_reporter import endpoint_progress, prepare
from diagnosis.replay.recorder import ReplaySession
from diagnosis.result import DiagnosisFinding

logger = logging.getLogger(__name__)

_DIR = Path(__file__).resolve().parent


def _run_screenshot_capture(
    ctx: DiagnosisContext,
    findings: list[DiagnosisFinding],
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Capture evidence screenshots right after the 4-4 scan (5-2 integration pattern).

    Loads screenshot/modules/4-4/module.py by path (the dir name isn't a valid Python
    identifier) and hands it the in-memory findings + already-authenticated sessions so
    it doesn't re-login. Any failure here is reported but never breaks the diagnosis.
    """
    cfg = ctx.raw_config.get("diagnosis_4_4") or {}
    if cfg.get("screenshot_enabled") is False:
        return {"enabled": False, "reason": "disabled_by_config"}

    module_path = ctx.data_dir.parent / "screenshot" / "modules" / "4-4" / "module.py"
    if not module_path.is_file():
        return {"enabled": False, "reason": "module_missing", "module": str(module_path)}

    try:
        spec = importlib.util.spec_from_file_location("screenshot_g44_module", module_path)
        if spec is None or spec.loader is None:
            return {"enabled": False, "reason": "module_load_failed"}
        mod = importlib.util.module_from_spec(spec)
        sys.modules["screenshot_g44_module"] = mod
        spec.loader.exec_module(mod)

        result = mod.capture_from_findings(ctx, findings, sessions=sessions)
        return {
            "enabled": True,
            "ok": bool(result.ok),
            "message": result.message,
            "cases_total": result.cases_total,
            "screenshots_total": result.screenshots_total,
            "evidence_dir": result.evidence_dir,
            "manifest": result.manifest_path,
        }
    except Exception as exc:  # never let screenshot failure break diagnosis
        logger.exception("4-4 screenshot capture failed")
        return {"enabled": True, "ok": False, "error": str(exc)[:300]}


def _load_local(name: str):
    mod_name = f"diag_g44_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"4-4 {name} 모듈을 불러올 수 없습니다")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class ScanResult:
    findings: list[DiagnosisFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""


def run_g44_scan(ctx: DiagnosisContext, module_dir: Path) -> ScanResult:
    raw = ctx.raw_config or {}
    cfg = raw.get("diagnosis_4_4") or {}
    targets = _load_local("targets")
    candidates_mod = _load_local("candidates")
    probes = _load_local("probes")
    transport_mod = _load_local("transport")
    tree, scoped, bases, login_report = targets.load_targets(ctx.data_dir, raw)
    if tree is None or not tree.endpoints:
        return ScanResult(status="error", message="api-tree가 없습니다. 먼저 인벤토리를 생성하세요.")
    if not scoped:
        return ScanResult(status="skipped", message="대시보드 Base URL 범위에 해당하는 엔드포인트가 없습니다.", stats={"inventory_endpoints": len(tree.endpoints)})

    extra_bases = [str(v).rstrip("/") for v in cfg.get("extra_base_urls", []) if str(v).strip()]
    bases = list(dict.fromkeys([*bases, *extra_bases]))
    candidates = candidates_mod.select_candidates(
        scoped, module_dir=module_dir, bases=bases,
        min_score=int(cfg.get("min_score", 2)), max_count=0 if bool(cfg.get("scan_all_inventory", False)) else int(cfg.get("max_candidates", 80)),
        scan_all_inventory=bool(cfg.get("scan_all_inventory", False)),
        forced_browse_enabled=bool(cfg.get("forced_browse_enabled", True)),
        include_frontend=bool(cfg.get("include_frontend", True)),
        include_write_methods=bool(cfg.get("include_write_methods", False)),
        extra_protected_paths=list(cfg.get("extra_protected_paths", [])),
    )
    if not candidates:
        return ScanResult(status="no_targets", message="인증이 필요한 중요 페이지 후보가 없습니다.", stats={"inventory_endpoints": len(tree.endpoints), "scoped_endpoints": len(scoped)})

    prepare(len(candidates), f"4-4: 중요 페이지 후보 {len(candidates)}개")
    pool = DiagnosisAuthPool(raw, data_dir=ctx.data_dir)
    pool.ensure_valid()
    sessions = pool.sessions()
    replay = ReplaySession(section_id="4-4", artifacts_root=section_evidence_dir(ctx.data_dir, "4-4"), raw_config=raw, account_auth=pool.primary())

    # 두 클라이언트의 쿠키 저장소는 공유되지 않으므로 인증 정보가 익명 pass로 역류하지 않음
    with transport_mod.HttpxTransport() as anonymous_transport, transport_mod.HttpxTransport() as authenticated_transport:
        findings, probe_stats = probes.run_page_probes(
            candidates, anonymous_transport=anonymous_transport,
            authenticated_transport=authenticated_transport, sessions=sessions,
            login_report=login_report, replay_session=replay,
            on_progress=endpoint_progress(total=len(candidates), phase_name="httpx", prefix="4-4 "),
        )
    high = sum(f.severity == "high" for f in findings)
    medium = sum(f.severity == "medium" for f in findings)
    status = "fail" if high else "warn" if medium else "pass"
    message = f"4-4 진단 완료: HIGH {high}건, MEDIUM {medium}건 (후보 {len(candidates)}개)"

    # findings가 비어도 호출한다 → 재진단으로 취약점이 사라진 경우 옛 증거를 비운다
    # (capture_from_findings가 회차 시작 시 evidence를 정리함).
    screenshot_stats = _run_screenshot_capture(ctx, findings, sessions)

    stats = {
        "inventory_endpoints": len(tree.endpoints), "scoped_endpoints": len(scoped),
        "candidates": len(candidates), "bases": bases, "httpx": probe_stats,
        "auth_refresh_count": pool.refresh_count, "auth_source": pool.meta.get("source"),
        "screenshots": screenshot_stats,
    }
    return ScanResult(findings=findings, stats=stats, status=status, message=message)
