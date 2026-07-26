"""Tests for 6-2 login enumeration probes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "6-2"


def _load(name: str):
    mod_name = f"diag_g62_{name}_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


class _FakeComparison:
    def __init__(self, *, uniform: bool, differences: list[str] | None = None) -> None:
        self.uniform = uniform
        self.differences = differences or []

    def to_dict(self) -> dict:
        return {"uniform": self.uniform, "differences": self.differences}


def _run_with_fake_http(*, uniform: bool):
    probes = _load("probes")
    rules = _load("login_rules")

    def fake_post_login(*_args, **_kwargs):
        return 401, '{"message":"인증에 실패하였습니다."}', "application/json", None, "json"

    probes._post_login = fake_post_login  # type: ignore[method-assign]

    compare = _FakeComparison(
        uniform=uniform,
        differences=[] if uniform else ["HTTP status differs: 401 vs 404"],
    )

    return probes.run_login_enumeration_probes(
        [{"url": "http://localhost:8080/api/v1/auth/login", "label": "localhost·login"}],
        auth_cfg={"id_field": "email", "pw_field": "password"},
        account_email="user@example.com",
        account_password="secret",
        snapshot_fn=rules.snapshot_from_http,
        compare_set_fn=lambda _scenarios, strict=True: compare,
        fake_email="argus-probe-test@invalid.example",
    )


def test_uniform_probe_does_not_emit_finding():
    findings, stats = _run_with_fake_http(uniform=True)
    assert stats["uniform"] == 1
    assert stats["enumeration_risk"] == 0
    assert findings == []


def test_enumeration_risk_still_emits_finding():
    findings, stats = _run_with_fake_http(uniform=False)
    assert stats["uniform"] == 0
    assert stats["enumeration_risk"] == 1
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "enumeration" in findings[0].message.lower()
