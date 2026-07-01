"""Tests for guideline 2-2 cross-account IDOR probes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.schema import Endpoint, InputParam, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "2-2"


def _load(name: str):
    mod_name = f"test_g22_idor_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _export_ep(**kwargs) -> Endpoint:
    defaults = {
        "method": "GET",
        "path": "/api/v1/admin/bookings/flights/{scheduleId}/export",
        "base_url": "http://localhost:8080",
        "kind": "api",
        "request_params": [InputParam(in_="path", name="scheduleId", sample="42")],
    }
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_is_idor_candidate_export_path():
    idor = _load("idor_probe")
    assert idor.is_idor_candidate(_export_ep())
    assert not idor.is_idor_candidate(
        Endpoint(method="GET", path="/api/health", base_url="http://localhost:8080", kind="api")
    )


def test_path_param_sets_uses_sample_and_seeds():
    idor = _load("idor_probe")
    ep = _export_ep()
    sets = idor.path_param_sets(ep, seeds={"scheduleId": ["7", "99"]})
    assert {"scheduleId": "42"} in sets
    assert {"scheduleId": "7"} in sets
    assert {"scheduleId": "99"} in sets
    assert len(sets) <= idor.MAX_PARAM_SETS


def test_path_param_sets_path_specific_seed():
    idor = _load("idor_probe")
    ep = _export_ep()
    path = ep.path
    sets = idor.path_param_sets(ep, seeds={path: {"scheduleId": "55"}})
    assert {"scheduleId": "55"} in sets


def test_classify_idor_same_file_high():
    auth = _load("auth_access")
    idor = _load("idor_probe")
    body = b"%PDF-1.4 export content here" + b"x" * 200
    owner = auth.AuthProbeSnapshot(
        auth_mode="owner",
        http_status=200,
        body=body,
        headers={"Content-Type": "application/pdf"},
        url="http://localhost:8080/export/42",
        account_email="owner@test.com",
    )
    other = auth.AuthProbeSnapshot(
        auth_mode="other",
        http_status=200,
        body=body,
        headers={"Content-Type": "application/pdf"},
        url="http://localhost:8080/export/42",
        account_email="other@test.com",
    )
    result = idor.classify_idor(
        path="/api/v1/admin/bookings/flights/{scheduleId}/export",
        path_params={"scheduleId": "42"},
        owner=owner,
        other=other,
    )
    assert result is not None
    severity, trigger, meta = result
    assert severity == "high"
    assert trigger == "idor_same_file_cross_account"
    assert meta["bodies_identical"] is True


def test_classify_idor_other_denied_no_finding():
    auth = _load("auth_access")
    idor = _load("idor_probe")
    body = b"%PDF-1.4 export content here" + b"x" * 200
    owner = auth.AuthProbeSnapshot(
        auth_mode="owner",
        http_status=200,
        body=body,
        headers={"Content-Type": "application/pdf"},
        url="http://localhost:8080/export/42",
        account_email="owner@test.com",
    )
    other = auth.AuthProbeSnapshot(
        auth_mode="other",
        http_status=403,
        body=b"forbidden",
        headers={"Content-Type": "application/json"},
        url="http://localhost:8080/export/42",
        account_email="other@test.com",
    )
    assert (
        idor.classify_idor(
            path="/api/v1/admin/bookings/flights/{scheduleId}/export",
            path_params={"scheduleId": "42"},
            owner=owner,
            other=other,
        )
        is None
    )


class IdorMockTransport:
    def __init__(self) -> None:
        self.file_body = b"%PDF-1.4 leaked export" + b"0" * 256

    def request(self, method, url, headers, body=None, *, follow_redirects=True):
        _ = method, body, follow_redirects
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if "owner-token" in auth:
            return _load("transport").ProbeResponse(
                status=200,
                body=self.file_body,
                headers={"Content-Type": "application/pdf"},
            )
        if "other-token" in auth:
            return _load("transport").ProbeResponse(
                status=200,
                body=self.file_body,
                headers={"Content-Type": "application/pdf"},
            )
        return _load("transport").ProbeResponse(status=403, body=b"", headers={})


def test_run_idor_probes_finds_cross_account_leak():
    idor = _load("idor_probe")
    ep = _export_ep()
    accounts = [
        {"email": "owner@test.com", "token": "owner-token", "Authorization": "Bearer owner-token"},
        {"email": "other@test.com", "token": "other-token", "Authorization": "Bearer other-token"},
    ]
    findings, stats = idor.run_idor_probes(
        [ep],
        account_auths=accounts,
        transport=IdorMockTransport(),
        engine="httpx",
    )
    assert stats["skipped_insufficient_accounts"] is False
    assert stats["owner_hits"] >= 1
    assert len(findings) == 1
    assert findings[0].evidence["rule_id"] == "2-2-idor"
    assert findings[0].severity == "high"
    assert "owner@test.com" in findings[0].message
    assert "other@test.com" in findings[0].message


def test_run_idor_skipped_single_account():
    idor = _load("idor_probe")
    findings, stats = idor.run_idor_probes(
        [_export_ep()],
        account_auths=[{"email": "solo@test.com", "token": "solo"}],
        transport=IdorMockTransport(),
        engine="httpx",
    )
    assert findings == []
    assert stats["skipped_insufficient_accounts"] is True
