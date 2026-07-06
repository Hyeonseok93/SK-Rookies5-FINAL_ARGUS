"""Diagnosis module 4-2: 인증(세션 및 토큰) 값 안전성 설정 여부."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g42_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load 4-2 scanner")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g42_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


class G42Module(DiagnosisModule):
    section_id = "4-2"
    title = "인증(세션 및 토큰) 값 안전성 설정 여부"
    chapter = 4
    implemented = False
    diagnosable = False
    status_label = "수동 진단"
    engine = "pending"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir
        manifest = module_dir / "manifest.yaml"
        if manifest.is_file():
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.title = str(raw.get("title", self.title))
                self.chapter = int(raw.get("chapter", self.chapter))
                self.implemented = bool(raw.get("implemented", self.implemented))
                self.diagnosable = bool(raw.get("diagnosable", self.diagnosable))
                self.review_later = bool(raw.get("review_later", False))
                self.status_label = (
                    str(raw["status_label"]).strip() if raw.get("status_label") else None
                )
                self.engine = str(raw.get("engine", self.engine))

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        scanner = _load_scanner()
        result = scanner.run_g42_scan(ctx, self.module_dir)

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
                    message="4-2 scan statistics",
                    evidence={"stats": result.stats},
                ),
            )
        self.save_report(ctx, report)
        return report


module = G42Module(_MODULE_DIR)
