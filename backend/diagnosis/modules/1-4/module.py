"""Diagnosis module 1-4: SSRF / File Inclusion 공격 가능성."""
from __future__ import annotations

import sys
import re
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.probe_auth import all_account_auths_with_meta
from diagnosis.replay.normalize import filter_endpoints_by_probe_bases
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso
from diagnosis.progress_reporter import endpoint_progress, prepare
from inventory.auth_util import auth_headers
from inventory.load import load_api_tree
from app.services.test_accounts_service import load_test_accounts

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from inventory_bridge import endpoints_to_scan_targets  # noqa: E402
from main import run_pipeline  # noqa: E402
from report_mapper import build_findings, build_status_and_message  # noqa: E402


def _scan_options(raw: dict) -> dict:
    cfg = raw.get("diagnosis_1_4") or {}
    return {
        "use_zap": bool(cfg.get("zap_enabled", False)),
        "oob_enabled": bool(cfg.get("oob_enabled", False)),
        "oob_callback_domain": str(cfg.get("oob_domain", "")),
        "whitelisted_domain": str(cfg.get("whitelisted_domain", "example.com")),
    }


def _result_key(result: dict) -> tuple[str, str, str, str]:
    return (
        str(result.get("method") or "").upper(),
        str(result.get("url") or ""),
        str(result.get("param") or ""),
        str(result.get("vuln_type") or ""),
    )


def _dedupe_session_results(results: list[dict]) -> list[dict]:
    """Merge account duplicates while preserving every confirming role."""
    deduped: dict[tuple[str, str, str, str], dict] = {}
    for result in results:
        key = _result_key(result)
        roles = {str(role) for role in result.get("confirmed_by_roles") or [] if role}
        if key not in deduped:
            item = dict(result)
            item["confirmed_by_roles"] = sorted(roles)
            deduped[key] = item
            continue
        existing = deduped[key]
        roles.update(str(role) for role in existing.get("confirmed_by_roles") or [] if role)
        existing["confirmed_by_roles"] = sorted(roles)
    return list(deduped.values())


def _audit_role_name(session: dict) -> str:
    raw_role = str(session.get("role") or session.get("login_label") or "ACCOUNT").upper()
    return re.sub(r"[^A-Z0-9_-]+", "_", raw_role).strip("_") or "ACCOUNT"


class G14Module(DiagnosisModule):
    section_id = "1-4"
    title = "SSRF / File Inclusion 공격 가능성"
    chapter = 1
    implemented = True
    engine = "custom-injector+zap"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir
        manifest = module_dir / "manifest.yaml"
        if manifest.is_file():
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.title = str(raw.get("title", self.title))
                self.chapter = int(raw.get("chapter", self.chapter))
                self.engine = str(raw.get("engine", self.engine))

    def _error_report(self, ctx: DiagnosisContext, message: str) -> SectionReport:
        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status="error",
            implemented=True,
            message=message,
            checked_at=utc_now_iso(),
        )
        self.save_report(ctx, report)
        return report

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        raw = ctx.raw_config or {}
        opts = _scan_options(raw)
        tree = load_api_tree(ctx.data_dir)
        if tree is None or not tree.endpoints:
            return self._error_report(
                ctx,
                "api-tree가 없습니다 - 인벤토리를 먼저 빌드하세요 (data/api-tree-ready.json)",
            )

        scoped = filter_endpoints_by_probe_bases(tree.endpoints, raw)
        targets = endpoints_to_scan_targets(scoped)
        prepare(len(targets), f"1-4: {len(targets)}개 인벤토리 대상 준비")
        accounts = load_test_accounts().get("accounts") or []
        if not accounts:
            return self._error_report(
                ctx,
                "테스트 계정이 설정되지 않았습니다 - 대시보드에서 테스트 계정을 먼저 "
                "등록하세요 (인증 없는 스캔은 지원하지 않음)",
            )

        sessions, auth_meta = all_account_auths_with_meta(raw, data_dir=ctx.data_dir)
        if not sessions:
            return self._error_report(
                ctx,
                "테스트 계정은 등록되어 있지만 로그인에 실패했습니다 - 로그인 엔드포인트, "
                f"계정 정보 및 대상 서버 상태를 확인하세요 (auth_source={auth_meta.get('source')})",
            )

        merged_all: list[dict] = []
        for session in sessions:
            headers = auth_headers(session)
            role = _audit_role_name(session)

            def _refresh(session=session):
                fresh, _meta = all_account_auths_with_meta(
                    raw, data_dir=ctx.data_dir, refresh=True
                )
                email = session.get("email")
                match = next((item for item in fresh if item.get("email") == email), None)
                return auth_headers(match) if match else None

            session_results = run_pipeline(
                    precomputed_targets=targets,
                    output_path=str(self.module_dir / f"_last_run.{role}.json"),
                    use_zap=opts["use_zap"],
                    zap_api_url=(raw.get("zap") or {}).get("proxy", "http://zap:8090"),
                    zap_api_key=(raw.get("zap") or {}).get("api_key", ""),
                    oob_enabled=opts["oob_enabled"],
                    oob_callback_domain=opts["oob_callback_domain"],
                    whitelisted_domain=opts["whitelisted_domain"],
                    auth_headers=headers,
                    auth_refresh_callback=_refresh,
                    scan_role=role,
                    on_progress=endpoint_progress(
                        total=len(targets),
                        phase_name="probe",
                        prefix=f"1-4 {session.get('email') or 'account'} ",
                    ),
                )
            for result in session_results:
                item = dict(result)
                item["confirmed_by_roles"] = [role]
                merged_all.append(item)

        merged_unique = _dedupe_session_results(merged_all)
        findings: list[DiagnosisFinding] = build_findings(merged_unique)
        status, message = build_status_and_message(
            findings, candidate_count=len(merged_unique), target_count=len(targets)
        )
        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status=status,
            implemented=True,
            findings=findings,
            message=message,
            checked_at=utc_now_iso(),
        )
        self.save_report(ctx, report)
        return report


module = G14Module(_MODULE_DIR)
