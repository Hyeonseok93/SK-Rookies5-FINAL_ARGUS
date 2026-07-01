"""Tests for guideline 3-6 backup/test file rules and targets."""

from pathlib import Path

import pytest

def _load_g36(name: str):
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "3-6"
    path = root / f"{name}.py"
    mod_name = f"test_g36_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def file_rules():
    return _load_g36("file_rules")


@pytest.fixture(scope="module")
def targets_mod():
    return _load_g36("targets")


def test_classify_env_leak(file_rules):
    issue = file_rules.classify_file_response(
        "/.env",
        http_status=200,
        body="DB_PASSWORD=secret\nAPP_KEY=abc",
        content_type="text/plain",
    )
    assert issue is not None
    assert issue.severity == "high"
    assert issue.file_type == "env_secrets"


def test_classify_spa_fallback_skipped(file_rules):
    spa = '<!doctype html><html><body><div id="root"></div></body></html>'
    fp = file_rules._body_fingerprint(spa)
    issue = file_rules.classify_file_response(
        "/backup.zip",
        http_status=200,
        body=spa,
        content_type="text/html",
        baseline_fp=fp,
    )
    assert issue is None


def test_wordlist_has_backup_paths(targets_mod):
    paths, meta = targets_mod._load_wordlist_paths()
    assert meta["wordlist_total"] > 20
    assert "/backup.zip" in paths
    assert "/phpinfo.php" in paths


def test_build_probe_targets_requires_bases(targets_mod, monkeypatch):
    monkeypatch.setattr(targets_mod, "collect_base_urls", lambda _raw: [])
    out, meta = targets_mod.build_probe_targets({})
    assert out == []
    assert meta["base_urls"] == 0
