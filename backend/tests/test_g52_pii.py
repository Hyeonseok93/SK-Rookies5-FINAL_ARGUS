"""Unit tests for 5-2 PII disclosure module."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "5-2"


def _load(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"test_g52_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    if str(_MODULE_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULE_DIR))
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_masked_phone_skipped():
    rules = _load("pii_rules")
    hits = rules.analyze_text("010-****-5678", field_path="phone")
    assert not hits


def test_dedupe_prefers_api_port_over_frontend():
    targets = _load("targets")
    from inventory.schema import Endpoint

    rows = [
        Endpoint(
            base_url="http://localhost:5173",
            path="/api/v1/members/me",
            method="GET",
            kind="api",
        ),
        Endpoint(
            base_url="http://localhost:8080",
            path="/api/v1/members/me",
            method="GET",
            kind="api",
        ),
    ]
    out = targets.dedupe_api_probe_endpoints(rows)
    assert len(out) == 1
    assert out[0].base_url == "http://localhost:8080"


def test_dedupe_admin_prefers_origin_with_admin_session():
    targets = _load("targets")
    from inventory.schema import Endpoint

    rows = [
        Endpoint(
            base_url="http://localhost:8081",
            path="/api/v1/admin/members",
            method="GET",
            kind="api",
        ),
        Endpoint(
            base_url="http://localhost:8080",
            path="/api/v1/admin/members",
            method="GET",
            kind="api",
        ),
    ]
    sessions = [
        {
            "email": "admin@ex.com",
            "token": "tok",
            "login_url": "http://localhost:8080/api/v1/auth/admin/login",
        }
    ]
    out = targets.dedupe_api_probe_endpoints(rows, sessions=sessions)
    assert len(out) == 1
    assert out[0].base_url == "http://localhost:8080"


def test_timestamp_not_phone_false_positive():
    rules = _load("pii_rules")
    hits = rules.analyze_text(
        '{"success":false,"timestamp":"2026-07-01T11:16:57.069798308"}',
        field_path="body",
    )
    assert not any(h.rule_id == "phone_plain" for h in hits)


def test_plain_mobile_phone_detected():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"mobile":"010-1234-5678"}', field_path="body")
    assert any(h.rule_id == "phone_plain" for h in hits)


def test_audit_sensitive_email_field():
    rules = _load("pii_rules")
    audit = rules.audit_sensitive_values('{"email":"yerin@travel.com"}')
    assert audit["emails_seen"] == 1
    assert audit["sensitive_fields"] == 1


def test_plain_email_detected():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"email":"user.real@company.co.kr"}', field_path="body")
    assert any(h.rule_id == "email_plain" for h in hits)


def test_masked_email_skipped():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"email":"u***@company.co.kr"}', field_path="body")
    assert not any(h.rule_id == "email_plain" for h in hits)


def test_korean_name_in_sensitive_field():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"insuredName":"홍길동"}', field_path="body")
    assert any(h.rule_id == "korean_name_plain" for h in hits)


def test_model_name_not_person_name():
    rules = _load("pii_rules")
    payload = '{"data":{"cars":[{"modelName":"스타리아"},{"modelName":"쏘나타"}]}}'
    hits = rules.analyze_text(payload, field_path="body")
    assert not any(h.rule_id == "korean_name_plain" for h in hits)


def test_catalog_array_name_not_person_name():
    rules = _load("pii_rules")
    payload = '{"data":{"cars":[{"name":"스타리아"}]}}'
    hits = rules.analyze_text(payload, field_path="body")
    assert not any(h.rule_id == "korean_name_plain" for h in hits)


def test_profile_name_still_detected():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"data":{"name":"김철수","email":"a@b.com"}}', field_path="body")
    assert any(h.rule_id == "korean_name_plain" for h in hits)


def test_three_char_surname_name_detected():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"displayName":"이영희"}', field_path="body")
    assert any(h.rule_id == "korean_name_plain" for h in hits)


def test_nickname_brand_name_not_flagged():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"data":{"name":"온데카","nickname":"에어루나"}}', field_path="body")
    assert not any(h.rule_id == "korean_name_plain" for h in hits)


def test_two_char_name_not_flagged():
    rules = _load("pii_rules")
    hits = rules.analyze_text('{"data":{"name":"예린"}}', field_path="body")
    assert not any(h.rule_id == "korean_name_plain" for h in hits)


def test_url_query_rrn():
    rules = _load("pii_rules")
    # Valid checksum RRN: 900101-1234565 (test vector)
    hits = rules.analyze_url_params("https://api.test/v1/user?rrn=900101-1234568")
    assert any(h.rule_id == "rrn_plain" for h in hits)


def test_normalize_field_path_for_merge():
    probes = _load("probes")
    assert (
        probes.normalize_field_path_for_merge("response_body.data.members[3].email")
        == "response_body.data.members[*].email"
    )
    assert probes.normalize_field_path_for_merge("response_body.data.email") == "response_body.data.email"


def test_collapse_auth_findings():
    probes = _load("probes")
    from diagnosis.result import DiagnosisFinding

    base_ev = {
        "rule_id": "phone_plain",
        "endpoint_id": "https://x:GET:/api/a",
        "direction": "response_body",
        "field_path": "body.phone",
        "marker": "010-1234-5678",
        "method": "GET",
        "url": "http://localhost:8080/api/a",
        "sample": "010-1234-5678",
    }
    items = [
        DiagnosisFinding(
            severity="high",
            message="[5-2][httpx][anonymous][response_body] leak",
            evidence={**base_ev, "auth_mode": "anonymous", "sample": "010-1111-1111"},
        ),
        DiagnosisFinding(
            severity="high",
            message="[5-2][httpx][authenticated:a@b:login][response_body] leak",
            evidence={**base_ev, "auth_mode": "authenticated:a@b:login", "sample": "010-2222-2222"},
        ),
    ]
    collapsed, stats = probes.collapse_findings(items)
    assert stats["collapsed_issues"] == 1
    assert len(collapsed[0].evidence.get("auth_modes", [])) == 2

    raw = probes.serialize_raw_findings(items)
    assert len(raw) == 2
    samples = {row["evidence"]["auth_mode"]: row["evidence"]["sample"] for row in raw}
    assert samples["anonymous"] == "010-1111-1111"
    assert samples["authenticated:a@b:login"] == "010-2222-2222"


def test_g52_module_implemented():
    from app.services import diagnosis_service

    row = next(r for r in diagnosis_service.catalog() if r["id"] == "5-2")
    assert row["implemented"] is True
    assert row["engine"] == "httpx"
