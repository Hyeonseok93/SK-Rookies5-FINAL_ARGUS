from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def _load_replay():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-2" / "replay.py"
    module_dir = path.parent
    spec = importlib.util.spec_from_file_location("g22_replay_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    sys.modules["g22_replay_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_runtime_url_rewrites_localhost_in_docker(monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    replay = _load_replay()
    assert replay._runtime_url("http://localhost:8080/api/v1/auth/login") == (
        "http://host.docker.internal:8080/api/v1/auth/login"
    )


def test_build_probes_uses_probe_url_on_endpoint(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "api-tree.json").write_text(
        """
{
  "endpoints": [
    {
      "method": "GET",
      "path": "/api/v1/files/{fileId}",
      "base_url": "http://localhost:8080",
      "request_params": [
        {"name": "fileId", "in": "path", "required": true, "type": "string"}
      ],
      "tags": [],
      "sources": ["test"],
      "auth": [],
      "kind": "api"
    }
  ]
}
""",
        encoding="utf-8",
    )
    replay = _load_replay()
    evidence = {
        "rule_id": "2-2-path-traversal",
        "method": "GET",
        "path": "/api/v1/files/{fileId}",
        "base_url": "http://localhost:8080",
        "param": "fileId",
        "param_in": "path",
        "payload": "../../etc/passwd",
    }
    baseline_probe, attack_probe = replay.build_probes(
        evidence,
        data_dir=data_dir,
        account_auth=None,
    )
    assert "host.docker.internal" in baseline_probe["url"]
    assert "host.docker.internal" in attack_probe["url"]
    assert "../../etc/passwd" in attack_probe["url"]


def test_unauth_download_builds_auth_and_anon_exchanges(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "api-tree.json").write_text(
        """
{
  "endpoints": [
    {
      "method": "POST",
      "path": "/api/v1/report/integrated",
      "base_url": "http://localhost:8080",
      "request_params": [],
      "tags": [],
      "sources": ["test"],
      "auth": [],
      "kind": "api"
    }
  ]
}
""",
        encoding="utf-8",
    )
    replay = _load_replay()
    evidence = {
        "rule_id": "2-2-unauth-download",
        "method": "POST",
        "path": "/api/v1/report/integrated",
        "base_url": "http://localhost:8080",
        "trigger": "unauth_download_both_sessions",
        "account_email": "yerin@travel.com",
    }
    auth_session = {
        "email": "yerin@travel.com",
        "token": "tok",
        "delivery": "cookie",
        "cookie_name": "accessToken",
    }
    baseline, attack = replay.build_case_exchanges(
        evidence,
        data_dir=data_dir,
        authenticated_auth=auth_session,
    )
    assert "host.docker.internal" in baseline.url
    assert "host.docker.internal" in attack.url
    assert "Cookie" in baseline.request_headers or "cookie" in {
        k.lower() for k in baseline.request_headers
    }
    assert "Cookie" not in attack.request_headers and "Authorization" not in attack.request_headers
