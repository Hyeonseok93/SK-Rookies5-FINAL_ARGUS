"""4-4: 비인증 상태로 중요 페이지 접근 가능성"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g44_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise ImportError("4-4 스캐너를 불러올 수 없습니다")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["diag_g44_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


class G44Module(DiagnosisModule):
    section_id = "4-4"
    title = "비인증 상태로 중요 page접근 가능성"
    chapter = 4
    implemented = True
    engine = "httpx"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir
        raw = yaml.safe_load((module_dir / "manifest.yaml").read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            self.title = str(raw.get("title", self.title))
            self.chapter = int(raw.get("chapter", self.chapter))
            self.engine = str(raw.get("engine", self.engine))

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        result = _load_scanner().run_g44_scan(ctx, self.module_dir)
        report = SectionReport(
            section_id=self.section_id, title=self.title, chapter=self.chapter,
            status=result.status, implemented=True, findings=result.findings,
            message=result.message, checked_at=utc_now_iso(),
        )
        if result.stats:
            report.findings.insert(0, DiagnosisFinding(
                severity="info", message="4-4 진단 통계", evidence={"stats": result.stats},
            ))
        self.save_report(ctx, report)
        return report


module = G44Module(_MODULE_DIR)
