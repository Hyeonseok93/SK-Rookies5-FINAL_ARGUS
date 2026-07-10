"""Tests for diagnosis auth session pool."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from diagnosis.auth_session_pool import (
    DiagnosisAuthPool,
    earliest_session_expiry,
    jwt_expiry_epoch,
    resolve_refresh_margin_sec,
)


def _jwt_with_exp(exp: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "a@b.com", "exp": exp}).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}.sig"


def test_jwt_expiry_epoch_parses_exp():
    exp = int(time.time()) + 3600
    assert jwt_expiry_epoch(_jwt_with_exp(exp)) == float(exp)


def test_earliest_session_expiry():
    soon = int(time.time()) + 100
    later = int(time.time()) + 5000
    sessions = [
        {"token": _jwt_with_exp(later)},
        {"access_token": _jwt_with_exp(soon)},
    ]
    assert earliest_session_expiry(sessions) == float(soon)


def test_resolve_refresh_margin_sec_defaults():
    assert resolve_refresh_margin_sec({}) == 300


def test_pool_refresh_on_start(monkeypatch, tmp_path: Path):
    calls: list[bool] = []

    def fake_resolve(auth_cfg, accounts, *, data_dir=None, refresh=False):
        calls.append(refresh)
        return [{"email": "a@b.com", "token": _jwt_with_exp(int(time.time()) + 3600)}], {
            "source": "live_login",
            "sessions": 1,
        }

    monkeypatch.setattr(
        "diagnosis.probe_auth.all_account_auths_with_meta",
        lambda raw, *, data_dir=None, refresh=False: fake_resolve(
            {}, [], data_dir=data_dir, refresh=refresh
        ),
    )

    pool = DiagnosisAuthPool({}, data_dir=tmp_path)
    assert calls == [True]
    assert len(pool.sessions()) == 1
    assert pool.refresh_count == 1


def test_ensure_valid_refreshes_near_expiry(monkeypatch, tmp_path: Path):
    refresh_calls = 0

    def fake_resolve(auth_cfg, accounts, *, data_dir=None, refresh=False):
        nonlocal refresh_calls
        refresh_calls += 1
        exp = int(time.time()) + (120 if refresh_calls == 1 else 3600)
        return [{"email": "a@b.com", "token": _jwt_with_exp(exp)}], {
            "source": "live_login",
            "sessions": 1,
        }

    monkeypatch.setattr(
        "diagnosis.probe_auth.all_account_auths_with_meta",
        lambda raw, *, data_dir=None, refresh=False: fake_resolve(
            {}, [], data_dir=data_dir, refresh=refresh
        ),
    )

    pool = DiagnosisAuthPool({}, data_dir=tmp_path, refresh_margin_sec=300)
    assert refresh_calls == 1
    assert pool.ensure_valid() is True
    assert refresh_calls == 2
    assert pool.refresh_count == 2


def test_ensure_valid_skips_when_token_fresh(monkeypatch, tmp_path: Path):
    refresh_calls = 0

    def fake_resolve(auth_cfg, accounts, *, data_dir=None, refresh=False):
        nonlocal refresh_calls
        refresh_calls += 1
        exp = int(time.time()) + 7200
        return [{"email": "a@b.com", "token": _jwt_with_exp(exp)}], {
            "source": "live_login",
            "sessions": 1,
        }

    monkeypatch.setattr(
        "diagnosis.probe_auth.all_account_auths_with_meta",
        lambda raw, *, data_dir=None, refresh=False: fake_resolve(
            {}, [], data_dir=data_dir, refresh=refresh
        ),
    )

    pool = DiagnosisAuthPool({}, data_dir=tmp_path, refresh_margin_sec=300)
    assert pool.ensure_valid() is False
    assert pool.refresh_count == 1
