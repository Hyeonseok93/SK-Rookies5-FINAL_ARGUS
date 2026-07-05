"""Tests for 2-1 malicious file upload module."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-1"


def _load(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"test_g21_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_judge_upload_rejects_forbidden():
    judge = _load("upload_judge")
    response = httpx.Response(403, json={"message": "blocked"})
    result = judge.judge_upload_response(
        suite="test",
        method="POST",
        endpoint="/api/v1/posts",
        filename="shell.php",
        attack_desc="test",
        response=response,
    )
    assert result.verdict == "safe"


def test_judge_upload_flags_accepted_malicious():
    judge = _load("upload_judge")
    response = httpx.Response(
        201,
        json={"data": {"imageUrls": ["http://example.com/uploads/shell.php"]}},
    )
    result = judge.judge_upload_response(
        suite="test",
        method="POST",
        endpoint="/api/v1/posts",
        filename="shell.php",
        attack_desc="test",
        response=response,
    )
    assert result.verdict == "vulnerable"
    assert result.stored_url == "http://example.com/uploads/shell.php"


def test_g21_module_registered():
    from diagnosis.registry import get_module

    mod = get_module("2-1")
    assert mod is not None
    assert mod.implemented is True
    assert mod.engine == "httpx"


def test_g21_scan_skips_without_seller_credentials():
    from diagnosis.context import DiagnosisContext

    scanner = _load("scanner")
    ctx = DiagnosisContext(data_dir=Path("data"), raw_config={})
    result = scanner.run_g21_scan(ctx, _MODULE_DIR)
    assert result.status == "skipped"
    assert "셀러" in result.message
