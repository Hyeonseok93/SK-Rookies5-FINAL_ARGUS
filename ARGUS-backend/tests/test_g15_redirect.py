"""Tests for guideline 1-5 redirect / CORS rules."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "1-5"


def _load(name: str):
    mod_name = f"test_g15_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_location_points_to_sink():
    rules = _load("redirect_rules")
    sink = "http://host.docker.internal:8001/argus-redirect-sink"
    assert rules.location_points_to_sink("http://host.docker.internal:8001/argus-redirect-sink/r/x/y", sink)
    assert rules.location_points_to_sink("//host.docker.internal:8001/argus-redirect-sink/r/a/b", sink)
    assert not rules.location_points_to_sink("http://evil.com/", sink)


def test_open_redirect_requires_baseline_diff():
    rules = _load("redirect_rules")
    sink = "http://127.0.0.1:8001/argus-redirect-sink"
    loc = "http://127.0.0.1:8001/argus-redirect-sink/r/run/p1"
    assert rules.is_external_open_redirect(302, loc, sink_base=sink, baseline_location=None)
    assert not rules.is_external_open_redirect(
        302, loc, sink_base=sink, baseline_location=loc
    )
    assert not rules.is_external_open_redirect(200, loc, sink_base=sink, baseline_location=None)


def test_phase_b_builds_append_jobs():
    targets = _load("targets")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            Endpoint(
                method="GET",
                path="/oauth2/redirect",
                base_url="http://localhost:5173",
                kind="frontend",
            ),
        ],
    )
    jobs = targets.build_phase_b_jobs(
        tree,
        sink_base="http://127.0.0.1:8001/argus-redirect-sink",
        run_id="run1",
        probe_mode="full",
        sample_size=10,
        max_jobs=50,
    )
    assert jobs
    assert all(j["phase"] == "B" for j in jobs)
    assert any("redirect=" in j["test_url"] for j in jobs)


def test_phase_a_fuzzes_query_param():
    targets = _load("targets")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            Endpoint(
                method="GET",
                path="/login",
                base_url="http://localhost:8080",
                kind="api",
                request_params=[
                    InputParam(in_="query", name="next", sample="/home", role="input"),
                ],
            ),
        ],
    )
    jobs = targets.build_phase_a_jobs(
        tree,
        sink_base="http://127.0.0.1:8001/argus-redirect-sink",
        run_id="run1",
        probe_mode="full",
        sample_size=10,
        max_params_per_endpoint=3,
        max_jobs=20,
    )
    assert len(jobs) == 1
    assert jobs[0]["phase"] == "A"
    assert jobs[0]["param_name"] == "next"
    assert "argus-redirect-sink" in jobs[0]["test_url"]


def test_cors_wildcard_with_credentials():
    rules = _load("redirect_rules")
    issues = rules.analyze_cors_headers(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        probe_origin="https://evil.example",
    )
    assert issues
    assert issues[0]["reason"] == "cors_wildcard_with_credentials"


def test_crossdomain_wildcard():
    rules = _load("redirect_rules")
    body = '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'
    issues = rules.analyze_crossdomain_xml(body)
    assert issues[0]["reason"] == "crossdomain_wildcard"
