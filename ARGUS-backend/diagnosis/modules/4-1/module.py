"""Diagnosis module 4-1: 쿠키(Cookie) 및 웹 스토리지(Web Storage) 조작 가능성 — 수동 진단."""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
