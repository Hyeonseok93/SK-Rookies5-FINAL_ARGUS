"""Diagnosis module 1-2: 삽입(Injection) 공격 가능성."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g12_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load 1-2 scanner")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g12_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


class G12Module(DiagnosisModule):
    section_id = "1-2"
    title = "삽입(Injection) 공격 가능성"
    chapter = 1
    implemented = True
    engine = "requests+zap"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir
        manifest = module_dir / "manifest.yaml"
        if manifest.is_file():
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.title = str(raw.get("title", self.title))
                self.chapter = int(raw.get("chapter", self.chapter))
                self.engine = str(raw.get("engine", self.engine))

    def _save_json_report(self, ctx: DiagnosisContext, report: SectionReport) -> None:
        report_dir = ctx.data_dir / "report" / self.section_id
        report_dir.mkdir(parents=True, exist_ok=True)
        payload = report.to_dict()
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        (report_dir / "latest.json").write_text(text, encoding="utf-8")
        checked_at = (report.checked_at or utc_now_iso()).replace(":", "").replace("+", "_").replace(".", "_")
        (report_dir / f"report_{checked_at}.json").write_text(text, encoding="utf-8")

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        scanner = _load_scanner()
        result = scanner.run_g12_scan(ctx, self.module_dir)

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
                    message="1-2 scan statistics",
                    evidence={"stats": result.stats},
                ),
            )
        self.save_report(ctx, report)
        self._save_json_report(ctx, report)
        return report


module = G12Module(_MODULE_DIR)
