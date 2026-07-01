"""Tests for 6-2 login_rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-2" / "login_rules.py"


def _load():
    mod_name = "diag_g62_login_rules_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_uniform_same_message():
    rules = _load()
    a = rules.snapshot_from_http(
        scenario="a",
        email="user@test.com",
        status=401,
        body='{"message":"Invalid credentials"}',
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="b",
        email="fake@test.com",
        status=401,
        body='{"message":"Invalid credentials"}',
        content_type="application/json",
    )
    result = rules.compare_login_snapshots(a, b)
    assert result.uniform is True


def test_uniform_three_scenarios():
    rules = _load()
    body = '{"message":"Invalid credentials"}'
    snaps = [
        rules.snapshot_from_http(
            scenario="exists_wrong_password",
            email="user@test.com",
            status=401,
            body=body,
            content_type="application/json",
        ),
        rules.snapshot_from_http(
            scenario="nonexistent_wrong_password",
            email="fake@test.com",
            status=401,
            body=body,
            content_type="application/json",
        ),
        rules.snapshot_from_http(
            scenario="nonexistent_valid_password",
            email="fake@test.com",
            status=401,
            body=body,
            content_type="application/json",
        ),
    ]
    result = rules.compare_login_snapshot_set(snaps)
    assert result.uniform is True


def test_enumeration_c_differs_from_a():
    rules = _load()
    a = rules.snapshot_from_http(
        scenario="exists_wrong_password",
        email="user@test.com",
        status=401,
        body='{"message":"Wrong password"}',
        content_type="application/json",
    )
    c = rules.snapshot_from_http(
        scenario="nonexistent_valid_password",
        email="fake@test.com",
        status=404,
        body='{"message":"User not found"}',
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="nonexistent_wrong_password",
        email="fake@test.com",
        status=404,
        body='{"message":"User not found"}',
        content_type="application/json",
    )
    result = rules.compare_login_snapshot_set([a, b, c])
    assert result.uniform is False
    assert len(result.differences) >= 1


def test_enumeration_different_status():
    rules = _load()
    a = rules.snapshot_from_http(
        scenario="a",
        email="user@test.com",
        status=401,
        body='{"message":"Wrong password"}',
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="b",
        email="fake@test.com",
        status=404,
        body='{"message":"User not found"}',
        content_type="application/json",
    )
    result = rules.compare_login_snapshots(a, b)
    assert result.uniform is False
    assert any("HTTP status" in d for d in result.differences)
    assert any("message" in d for d in result.differences)


def test_enumeration_different_message_same_status():
    rules = _load()
    a = rules.snapshot_from_http(
        scenario="a",
        email="user@test.com",
        status=400,
        body='{"message":"Bad password"}',
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="b",
        email="fake@test.com",
        status=400,
        body='{"message":"No such user"}',
        content_type="application/json",
    )
    result = rules.compare_login_snapshots(a, b)
    assert result.uniform is False


def test_nested_error_code_extracted():
    rules = _load()
    body = (
        '{"success":false,"message":"인증에 실패하였습니다.",'
        '"error":{"code":"AUTH-001","systemMessage":"인증에 실패하였습니다."},'
        '"timestamp":"2026-06-30T08:42:04.924490371"}'
    )
    snap = rules.snapshot_from_http(
        scenario="a",
        email="user@test.com",
        status=401,
        body=body,
        content_type="application/json",
    )
    assert snap.error_code == "AUTH-001"
    assert snap.primary_message == "인증에 실패하였습니다."
    assert snap.json_fields.get("error.code") == "AUTH-001"


def test_enumeration_nested_error_code_same_message():
    rules = _load()
    base = (
        '"success":false,"message":"인증에 실패하였습니다.",'
        '"error":{{"code":"{code}","systemMessage":"인증에 실패하였습니다."}}'
    )
    a = rules.snapshot_from_http(
        scenario="exists_wrong_password",
        email="user@test.com",
        status=401,
        body="{" + base.format(code="AUTH-001") + "}",
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="nonexistent_wrong_password",
        email="fake@test.com",
        status=401,
        body="{" + base.format(code="AUTH-404") + "}",
        content_type="application/json",
    )
    result = rules.compare_login_snapshots(a, b)
    assert result.uniform is False
    assert any("error code" in d for d in result.differences)


def test_timestamp_only_change_still_uniform():
    rules = _load()
    body_a = (
        '{"message":"Invalid credentials","error":{"code":"AUTH-001"},'
        '"timestamp":"2026-06-30T08:42:04.924490371"}'
    )
    body_b = (
        '{"message":"Invalid credentials","error":{"code":"AUTH-001"},'
        '"timestamp":"2026-06-30T09:00:00.000000000"}'
    )
    a = rules.snapshot_from_http(
        scenario="a",
        email="user@test.com",
        status=401,
        body=body_a,
        content_type="application/json",
    )
    b = rules.snapshot_from_http(
        scenario="b",
        email="fake@test.com",
        status=401,
        body=body_b,
        content_type="application/json",
    )
    result = rules.compare_login_snapshots(a, b, strict=True)
    assert result.uniform is True

