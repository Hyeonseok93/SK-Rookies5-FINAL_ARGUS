"""Diagnosis module 1-1: XSS / CSRF."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g11_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load 1-1 scanner.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class G11Module(DiagnosisModule):
    section_id = "1-1"
    title = "XSS / CSRF attack surface"
    chapter = 1
    implemented = True
    engine = "httpx+zap"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        scanner = _load_scanner()
        result = scanner.run_g11_scan(ctx, self.module_dir)
        findings = [
            item
            if isinstance(item, DiagnosisFinding)
            else DiagnosisFinding(
                severity=str(item.get("severity") or item.get("risk") or "info"),
                message=str(
                    item.get("vuln_type")
                    or item.get("alert")
                    or item.get("message")
                    or "1-1 finding"
                ),
                evidence=dict(item),
            )
            for item in result.findings
        ]
        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status=result.status,
            implemented=True,
            findings=findings,
            message=result.message,
            checked_at=utc_now_iso(),
        )
        self.save_report(ctx, report)
        return report


module = G11Module(_MODULE_DIR)
