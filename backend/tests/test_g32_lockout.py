"""Tests for guideline 3-2 lockout detection rules."""

import importlib.util
from pathlib import Path


def _load_lockout_rules():
    path = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "3-2" / "lockout_rules.py"
    mod_name = "test_g32_lockout_rules"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


rules = _load_lockout_rules()


def _snap(attempt: int, *, status: int, message: str, code: str = "AUTH-001"):
    return rules.snapshot_from_http(
        scenario=f"attempt_{attempt}",
        email="user@ex.com",
        status=status,
        body=(
            f'{{"message":"{message}","error":{{"code":"{code}"}},'
            f'"timestamp":"2026-06-30T08:42:0{attempt}.000"}}'
        ),
        content_type="application/json",
    )


def test_no_lockout_when_responses_identical():
    snaps = [_snap(i, status=401, message="invalid credentials") for i in range(1, 6)]
    result = rules.analyze_lockout_sequence(snaps, retry_after_headers=[None] * 5)
    assert not result.detected


def test_lockout_on_429():
    snaps = [
        _snap(1, status=401, message="invalid credentials"),
        _snap(2, status=401, message="invalid credentials"),
        _snap(3, status=429, message="too many requests"),
    ]
    result = rules.analyze_lockout_sequence(snaps, retry_after_headers=[None, None, "60"])
    assert result.detected
    assert result.detected_at_attempt == 3
    assert result.limit_type == "rate_limit"


def test_lockout_on_message_change():
    snaps = [
        _snap(1, status=401, message="invalid credentials", code="AUTH-001"),
        _snap(2, status=401, message="invalid credentials", code="AUTH-001"),
        _snap(3, status=401, message="account locked due to too many attempts", code="AUTH-LOCK"),
    ]
    result = rules.analyze_lockout_sequence(snaps, retry_after_headers=[None] * 3)
    assert result.detected
    assert result.limit_type == "response_message"


def test_lockout_on_nested_error_code_change():
    def _spring(attempt: int, code: str) -> rules.LoginResponseSnapshot:
        body = (
            f'{{"success":false,"message":"인증에 실패하였습니다.",'
            f'"error":{{"code":"{code}"}},'
            f'"timestamp":"2026-06-30T08:42:0{attempt}.000"}}'
        )
        return rules.snapshot_from_http(
            scenario=f"attempt_{attempt}",
            email="user@ex.com",
            status=401,
            body=body,
            content_type="application/json",
        )

    snaps = [_spring(1, "AUTH-001"), _spring(2, "AUTH-001"), _spring(3, "AUTH-LOCK")]
    result = rules.analyze_lockout_sequence(snaps, retry_after_headers=[None] * 3)
    assert result.detected
    assert result.detected_at_attempt == 3

