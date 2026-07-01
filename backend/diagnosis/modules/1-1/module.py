"""Diagnosis module 1-1: XSS / CSRF 공격 가능성"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
