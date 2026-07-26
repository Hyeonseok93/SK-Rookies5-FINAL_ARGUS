"""Diagnosis module 4-5: 일반계정 권한 상승 가능성."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent


def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g45_scanner", _MODULE_DIR / "scanner.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load 4-5 scanner")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["diag_g45_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod


class G45Module(DiagnosisModule):
    section_id = "4-5"
    title = "일반계정 권한 상승 가능성"
    chapter = 4
    implemented = True
    engine = "requests"

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
        
        if not ctx.raw_config:
            ctx.raw_config = {}
        if not ctx.raw_config.get("auth"):
            ctx.raw_config["auth"] = {}
        
        data_dir = Path(getattr(ctx, "data_dir", "data"))
        test_accounts_path = data_dir / "test-accounts.json"
        
        accounts = ctx.raw_config["auth"].get("accounts", [])
        if not accounts and test_accounts_path.is_file():
            import json
            try:
                raw_accounts = json.loads(test_accounts_path.read_text(encoding="utf-8")).get("accounts", [])
                ctx.raw_config["auth"]["accounts"] = raw_accounts
            except Exception:
                pass

        result = scanner.run_g45_scan(ctx, self.module_dir)

        findings = list(result.findings)
        if hasattr(result, "stats") and result.stats:
            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message="4-5 scan statistics",
                    evidence={"stats": result.stats},
                )
            )

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
        # The frontend will only display the actual vulnerabilities (result.findings)
        self.save_report(ctx, report)
        return report


module = G45Module(_MODULE_DIR)
