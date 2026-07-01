"""Diagnosis module 1-6: 입력 값 크기 및 무결성 검증 오류"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
