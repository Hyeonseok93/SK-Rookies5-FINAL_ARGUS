"""Diagnosis module 8-1: 취약점 진단 항목에 정의되지 않은 취약점"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
