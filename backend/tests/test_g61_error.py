"""Unit tests for 6-1 error-page disclosure module."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-1"


def _load(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"test_g61_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    if str(_MODULE_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULE_DIR))
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_all_payload_values_utf8_encodable():
    payloads = _load("payloads")
    suite = payloads.build_payload_suite([100])
    for spec in suite:
        assert payloads.utf8_encodable(spec.value), spec.payload_id


def test_payload_suite_covers_categories():
    payloads = _load("payloads")
    suite = payloads.build_payload_suite([100, 1000])
    categories = {p.category for p in suite}
    assert "korean" in categories
    assert "special" in categories
    assert "length" in categories
    assert any(p.payload_id == "long_1000" for p in suite)


def test_analyze_sql_exception():
    rules = _load("error_rules")
    hits = rules.analyze_error_response(
        status_code=500,
        headers={"content-type": "application/json"},
        body='{"message":"java.sql.SQLException: syntax error near foo"}',
    )
    assert any(h.rule_id == "sql_exception" for h in hits)


def test_analyze_java_stack():
    rules = _load("error_rules")
    body = "Error\n\tat com.example.app.Foo.bar(Foo.java:42)\nCaused by: java.lang.RuntimeException"
    hits = rules.analyze_error_response(status_code=500, headers={}, body=body)
    assert any(h.rule_id in ("java_stack", "java_caused") for h in hits)


def test_analyze_flags_404_with_message():
    rules = _load("error_rules")
    hits = rules.analyze_error_response(
        status_code=404,
        headers={"content-type": "application/json"},
        body='{"error":"not_found","message":"resource missing"}',
    )
    assert any(h.rule_id == "server_error_message" for h in hits)


def test_analyze_flags_onde_style_api_error():
    rules = _load("error_rules")
    hits = rules.analyze_error_response(
        status_code=401,
        headers={"content-type": "application/json"},
        body='{"success":false,"message":"인증에 실패하였습니다.","error":{"code":"AUTH-001","systemMessage":"인증에 실패하였습니다."}}',
    )
    assert any(h.rule_id == "json_system_message" for h in hits)
    assert any(h.rule_id == "server_error_message" for h in hits)


def test_analyze_skips_php_pattern_on_json():
    rules = _load("error_rules")
    hits = rules.analyze_error_response(
        status_code=500,
        headers={"content-type": "application/json"},
        body='{"message":"parse error: syntax error in /var/www/x.php"}',
    )
    assert not any(h.rule_id.startswith("php_") for h in hits)
    assert any(h.rule_id == "server_error_message" for h in hits)


def test_classify_sk_buckets():
    rules = _load("error_rules")
    assert rules.classify_sk(category="database", rule_id="sql_exception") == "dbms"
    assert rules.classify_sk(category="stack_trace", rule_id="java_stack") == "exception"
    assert rules.classify_sk(category="verbose_error", rule_id="verbose_500") == "http"
    assert rules.classify_sk(category="zap_error_disclosure", rule_id="6-1-zap-90022") == "http"


def test_analyze_java_stack_has_sk_exception():
    rules = _load("error_rules")
    body = "Error\n\tat com.example.app.Foo.bar(Foo.java:42)\nCaused by: java.lang.RuntimeException"
    hits = rules.analyze_error_response(status_code=500, headers={}, body=body)
    assert hits
    assert hits[0].sk_class == "exception"


def test_collapse_auth_findings_merges_sessions():
    probes = _load("probes")
    from diagnosis.result import DiagnosisFinding

    base_ev = {
        "rule_id": "java_stack",
        "endpoint_id": "https://x:GET:/api/a",
        "trigger_family": "param",
        "trigger_id": "param:query:id:ascii_alpha",
        "param_name": "id",
        "payload_id": "ascii_alpha",
    }
    items = [
        DiagnosisFinding(
            severity="high",
            message="[6-1][httpx][anonymous][param] leak",
            evidence={**base_ev, "auth_mode": "anonymous", "engine": "httpx"},
        ),
        DiagnosisFinding(
            severity="high",
            message="[6-1][httpx][authenticated:a@b:login][param] leak",
            evidence={**base_ev, "auth_mode": "authenticated:a@b:login", "engine": "httpx"},
        ),
    ]
    collapsed, stats = probes.collapse_auth_findings(items)
    assert stats["collapsed_leaks"] == 1
    assert len(collapsed[0].evidence.get("auth_modes", [])) == 2


def test_request_budget_unlimited():
    probes = _load("probes")
    budget = probes.RequestBudget(max_requests=0)
    for _ in range(500):
        assert budget.consume("param")
    assert budget.sent == 500
    assert budget.unlimited
    assert not budget.exhausted()


def test_request_budget_capped():
    probes = _load("probes")
    budget = probes.RequestBudget(max_requests=3)
    assert budget.consume("a")
    assert budget.consume("b")
    assert budget.consume("c")
    assert not budget.consume("d")
    assert budget.exhausted()


def test_build_url_rewrites_localhost_for_docker_probe(monkeypatch):
    triggers = _load("triggers")
    from inventory.schema import Endpoint

    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    ep = Endpoint(
        method="GET",
        path="/api/v1/cars",
        base_url="http://localhost:8080",
        kind="api",
    )
    url = triggers._build_url(ep, "/api/v1/cars", {"location": "../"})
    assert url.startswith("http://host.docker.internal:8080/")
    assert "location=" in url


def test_g61_module_implemented():
    from app.services import diagnosis_service

    row = next(r for r in diagnosis_service.catalog() if r["id"] == "6-1")
    assert row["implemented"] is True
    assert row["engine"] == "httpx"
