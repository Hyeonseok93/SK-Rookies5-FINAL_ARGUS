"""Tests for universal evidence replay."""

from __future__ import annotations

from pathlib import Path

from diagnosis.replay.normalize import (
    collect_probe_base_urls,
    normalize_url,
    pick_public_base_for_url,
    resolve_public_base_url,
)
from diagnosis.replay.recorder import ReplayRecorder
from diagnosis.replay.runner import run_replay_plan
from diagnosis.replay.schema import ReplayPlan
from diagnosis.result import DiagnosisFinding


def test_probe_url_localhost_unchanged_without_docker_env(monkeypatch):
    monkeypatch.delenv("ARGUS_PROBE_HOST", raising=False)
    from inventory.net import probe_url

    url = "http://localhost:8080/api/v1/members/me"
    assert probe_url(url) == url


def test_probe_url_rewrites_when_argus_probe_host_set(monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    from inventory.net import probe_url

    assert probe_url("http://localhost:8080/api") == "http://host.docker.internal:8080/api"


def test_normalize_docker_url_uses_dashboard_port_match():
    url = "http://host.docker.internal:5173/user-api/api/v1/report/integrated"
    out = normalize_url(
        url,
        dashboard_bases=["http://localhost:5174", "http://localhost:8080"],
    )
    assert out.startswith("http://localhost:5174/")
    assert "host.docker.internal" not in out


def test_normalize_docker_api_port():
    url = "http://host.docker.internal:8080/api/v1/auth/login"
    out = normalize_url(
        url,
        dashboard_bases=["http://localhost:5173", "http://localhost:8080"],
    )
    assert "localhost:8080" in out


def test_resolve_public_base_from_dashboard():
    bases = ["http://localhost:8080", "http://localhost:5174"]
    assert resolve_public_base_url({}, dashboard_bases=bases) == "http://localhost:5174"


def test_resolve_public_base_falls_back_to_inventory():
    raw = {
        "inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}},
    }
    assert resolve_public_base_url(raw, dashboard_bases=[]) == "http://localhost:5173"


def test_collect_probe_base_urls_dashboard_only(monkeypatch):
    from diagnosis.replay import normalize as norm

    monkeypatch.setattr(
        norm,
        "load_dashboard_base_urls",
        lambda: ["https://onde.click", "https://rookies.onde.click"],
    )
    raw = {
        "inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}},
        "targets": [
            {"base_url": "http://host.docker.internal:8080"},
            {"base_url": "http://host.docker.internal:8081"},
        ],
    }
    assert collect_probe_base_urls(raw) == [
        "https://onde.click",
        "https://rookies.onde.click",
    ]


def test_collect_probe_base_urls_dev_fallback_when_dashboard_empty(monkeypatch):
    from diagnosis.replay import normalize as norm

    monkeypatch.setattr(norm, "load_dashboard_base_urls", lambda: [])
    raw = {
        "inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}},
        "targets": [{"base_url": "http://localhost:8080"}],
    }
    assert collect_probe_base_urls(raw) == [
        "http://localhost:8080",
        "http://localhost:5173",
    ]


def test_filter_endpoints_by_probe_bases_dashboard_only(monkeypatch):
    from diagnosis.replay import normalize as norm
    from inventory.schema import Endpoint

    monkeypatch.setattr(
        norm,
        "load_dashboard_base_urls",
        lambda: ["https://onde.click"],
    )
    eps = [
        Endpoint(method="GET", path="/", base_url="https://onde.click"),
        Endpoint(method="GET", path="/", base_url="http://localhost:5173"),
        Endpoint(method="GET", path="/api", base_url="http://host.docker.internal:8080"),
    ]
    filtered = norm.filter_endpoints_by_probe_bases(eps, {})
    assert len(filtered) == 1
    assert filtered[0].base_url == "https://onde.click"


def test_pick_public_base_for_url_port_aware():
    url = "http://host.docker.internal:8081/api/v1/admin/foo"
    base = pick_public_base_for_url(
        url,
        dashboard_bases=["http://127.0.0.1:5173", "http://127.0.0.1:8081"],
    )
    assert base == "http://127.0.0.1:8081"


def test_recorder_attaches_replay_to_finding(tmp_path: Path):
    rec = ReplayRecorder(
        section_id="2-2",
        rule_id="test-rule",
        artifacts_root=tmp_path,
        raw_config={},
        path="/api/v1/demo",
        trigger="demo",
    )
    rec.set_auth("anonymous")
    rec.record_http(
        "probe",
        label="Demo probe",
        method="GET",
        url="http://host.docker.internal:5173/api/health",
        headers={"Accept": "application/json"},
        body=None,
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"ok":true}',
        auth_mode="anonymous",
    )
    # Override public base via resolve — patch via dashboard in normalize call path
    rec.public_base = "http://localhost:5173"
    finding = rec.attach_to(DiagnosisFinding(severity="high", message="demo", evidence={"rule_id": "test"}))
    replay = finding.evidence["replay"]
    assert finding.evidence["replayable"] is True
    assert replay["finding_id"]
    assert len(replay["steps"]) == 2
    assert replay["env"]["public_base_url"]


def test_playwright_cookies_from_login():
    from diagnosis.replay.browser_auth import playwright_cookies_from_login

    cookies = playwright_cookies_from_login(
        {
            "accessToken": "tok123",
            "refreshToken": "ref456",
            "memberId": 42,
            "role": "ROLE_USER",
            "expiresIn": 3600,
        },
        email="yerin@travel.com",
        base_url="http://localhost:5173",
    )
    names = {c["name"] for c in cookies}
    assert "onde_access_token" in names
    assert "onde_member_id" in names
    assert "onde_member_role" in names
    assert "onde_username" in names
    assert all(c["domain"] == "localhost" for c in cookies)
    by_name = {c["name"]: c["value"] for c in cookies}
    assert by_name["onde_username"] == "yerin@travel.com"
    assert by_name["onde_member_id"] == "42"


def test_run_replay_plan_httpx_only(tmp_path: Path):
    rec = ReplayRecorder(
        section_id="2-2",
        rule_id="test-rule",
        artifacts_root=tmp_path,
        raw_config={},
        path="/api/v1/demo",
    )
    rec.record_http(
        "probe",
        label="Health",
        method="GET",
        url="https://httpbin.org/status/200",
        headers={},
        body=None,
        response_status=200,
        response_headers={"content-type": "text/plain"},
        response_body=b"ok",
    )
    plan_dict = rec.finalize()

    plan = ReplayPlan.from_dict(plan_dict)
    plan.steps[-1].request.url = "https://httpbin.org/status/200"  # type: ignore[union-attr]
    if plan.steps[-1].expect:
        plan.steps[-1].expect.sha256 = ""

    result = run_replay_plan(
        plan,
        artifacts_root=tmp_path,
        use_playwright=False,
    )
    assert result.finding_id
    assert result.steps
    assert result.steps[-1].action == "http"
