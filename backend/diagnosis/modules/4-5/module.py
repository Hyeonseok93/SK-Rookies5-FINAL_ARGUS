"""Diagnosis module 4-5: 일반계정 권한 상승 가능성"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
