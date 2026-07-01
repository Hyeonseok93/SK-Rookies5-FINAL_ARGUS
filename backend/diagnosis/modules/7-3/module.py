"""Diagnosis module 7-3: 서버 헤더정보 노출."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g73_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load 7-3 scanner")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g73_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


class G73Module(DiagnosisModule):
    section_id = "7-3"
    title = "서버 헤더정보 노출"
    chapter = 7
    implemented = True
    engine = "httpx+zap"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir
        manifest = module_dir / "manifest.yaml"
        if manifest.is_file():
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.title = str(raw.get("title", self.title))
                self.chapter = int(raw.get("chapter", self.chapter))
                self.engine = str(raw.get("engine", self.engine))

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        scanner = _load_scanner()
        result = scanner.run_g73_scan(ctx, self.module_dir)

        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status=result.status,
            implemented=True,
            findings=result.findings,
            message=result.message,
            checked_at=utc_now_iso(),
        )
        if result.stats:
            report.findings.insert(
                0,
                DiagnosisFinding(
                    severity="info",
                    message="7-3 scan statistics",
                    evidence={"stats": result.stats},
                ),
            )
        self.save_report(ctx, report)
        return report


module = G73Module(_MODULE_DIR)
