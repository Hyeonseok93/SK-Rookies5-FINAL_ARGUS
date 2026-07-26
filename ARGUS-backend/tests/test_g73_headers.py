"""Tests for 7-3 server header disclosure rules."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "7-3"


def _load_rules():
    mod_name = "diag_g73_header_rules_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "header_rules.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_classify_server_with_version():
    rules = _load_rules()
    issue = rules.classify_header("Server", "nginx/1.24.0")
    assert issue is not None
    assert issue.severity == "medium"
    assert issue.reason == "version_disclosed"


def test_classify_server_product_only_strict():
    rules_mod = _load_rules()
    strict = rules_mod.ScanRules(strict=True)
    relaxed = rules_mod.ScanRules(strict=False)
    issue = rules_mod.classify_header("Server", "nginx", rules=strict)
    assert issue is not None
    assert issue.severity == "medium"
    relaxed_issue = rules_mod.classify_header("Server", "nginx", rules=relaxed)
    assert relaxed_issue is not None
    assert relaxed_issue.severity == "low"


def test_classify_version_only_value():
    rules = _load_rules()
    issue = rules.classify_header("Server", "9.0.50")
    assert issue is not None
    assert issue.severity == "medium"


def test_classify_php_slash_version():
    rules = _load_rules()
    issue = rules.classify_header("X-Powered-By", "PHP/8")
    assert issue is not None
    assert issue.severity == "medium"


def test_classify_x_powered_by():
    rules = _load_rules()
    issue = rules.classify_header("X-Powered-By", "Express")
    assert issue is not None
    assert issue.severity == "medium"  # strict default


def test_classify_x_generator_product_only():
    rules = _load_rules()
    issue = rules.classify_header("X-Generator", "WordPress")
    assert issue is not None
    assert issue.severity == "medium"


def test_classify_heuristic_custom_header_name():
    rules_mod = _load_rules()
    strict = rules_mod.ScanRules(strict=True)
    issue = rules_mod.classify_header("X-App-Backend-Version", "internal", rules=strict)
    assert issue is not None
    assert issue.severity == "medium"


def test_classify_environment_disclosure():
    rules = _load_rules()
    issue = rules.classify_header("X-Environment", "staging")
    assert issue is not None
    assert issue.reason == "environment_disclosed"
    assert issue.severity == "medium"


def test_classify_kestrel_product():
    rules = _load_rules()
    issue = rules.classify_header("Server", "Kestrel")
    assert issue is not None
    assert issue.severity == "medium"


def test_benign_server_hidden():
    rules = _load_rules()
    assert rules.classify_header("Server", "webserver") is None


def test_non_disclosure_header_ignored():
    rules = _load_rules()
    assert rules.classify_header("Content-Type", "application/json") is None
    assert rules.classify_header("X-Request-Id", "abc-123") is None


def test_cdn_header_only_when_enabled():
    rules_mod = _load_rules()
    off = rules_mod.ScanRules(include_cdn_headers=False)
    on = rules_mod.ScanRules(include_cdn_headers=True)
    assert rules_mod.classify_header("Via", "1.1 varnish", rules=off) is None
    assert rules_mod.classify_header("Via", "1.1 varnish", rules=on) is not None


def test_disclosure_header_count():
    rules = _load_rules()
    assert len(rules.DISCLOSURE_HEADERS) >= 20


def test_scan_response_headers_dedupes():
    rules = _load_rules()
    issues = rules.scan_response_headers(
        {
            "Server": "Apache/2.4.57 (Ubuntu)",
            "X-Powered-By": "PHP/8.2.0",
            "Content-Type": "text/html",
        }
    )
    names = {i.header for i in issues}
    assert "server" in names
    assert "x-powered-by" in names
    assert len(issues) == 2
    assert all(i.severity == "medium" for i in issues)


def test_scan_rules_from_config():
    rules = _load_rules()
    cfg = rules.scan_rules_from_config({"diagnosis_7_3": {"strict": False, "extra_headers": ["X-Custom"]}})
    assert cfg.strict is False
    assert "x-custom" in cfg.extra_headers


def test_build_probe_urls_from_config():
    mod_name = "diag_g73_targets_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "targets.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

    urls, meta = mod.build_probe_urls(
        {
            "targets": [{"base_url": "http://localhost:8080"}],
        },
        probe_mode="base_only",
    )
    assert urls
    assert meta["probe_mode"] == "base_only"
    assert urls[0]["probe_url"].startswith("http://")
    assert urls[0]["probe_url"].endswith("/")
