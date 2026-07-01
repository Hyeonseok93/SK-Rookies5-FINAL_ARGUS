"""Diagnosis module 1-3: 파라미터 값 및 히든(Hidden) 필드 조작 가능성"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
