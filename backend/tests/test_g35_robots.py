"""Tests for guideline 3-5 robots inventory rules and targets."""

from pathlib import Path

import pytest


def _load_g35(name: str):
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "3-5"
    path = root / f"{name}.py"
    mod_name = f"test_g35_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def rules():
    return _load_g35("robots_rules")


@pytest.fixture(scope="module")
def targets_mod():
    return _load_g35("targets")


def test_parse_meta_noindex(rules):
    html = '<html><head><meta name="robots" content="noindex, nofollow"></head></html>'
    directive = rules.parse_meta_robots(html)
    assert directive is not None
    assert directive.has_noindex
    assert directive.has_nofollow


def test_extract_page_signals_noindex(rules):
    html = '<html><head><meta name="robots" content="noindex,nofollow"></head></html>'
    sig = rules.extract_page_robots_signals(
        "http://example.com/admin",
        http_status=200,
        content_type="text/html",
        body=html,
        x_robots="",
    )
    assert sig is not None
    assert sig.has_noindex
    assert sig.has_any_directive


def test_extract_page_no_directive(rules):
    html = "<html><head><title>Home</title></head></html>"
    sig = rules.extract_page_robots_signals(
        "http://example.com/",
        http_status=200,
        content_type="text/html",
        body=html,
        x_robots="",
    )
    assert sig is not None
    assert not sig.has_any_directive


def test_parse_robots_txt_disallow(rules):
    body = "User-agent: *\nDisallow: /admin\nDisallow: /api\nSitemap: https://ex.com/sitemap.xml\n"
    info = rules.parse_robots_txt(body, status=200)
    assert info.present
    assert "/admin" in info.disallow_paths
    assert info.sitemaps


def test_build_probe_targets_base_only(targets_mod, monkeypatch):
    monkeypatch.setattr(targets_mod, "collect_base_urls", lambda _raw: ["http://localhost:8080"])
    out, meta = targets_mod.build_probe_targets({}, probe_mode="base_only")
    assert len(out) == 1
    assert out[0]["path"] == "/"
    assert meta["probe_mode"] == "base_only"


def test_include_page_endpoint_skips_api_json(targets_mod):
    from inventory.schema import Endpoint

    ep = Endpoint(method="GET", path="/api/v1/users", base_url="http://localhost:8080", kind="api")
    assert targets_mod._include_page_endpoint(ep, is_frontend=False) is False
    fe = Endpoint(method="GET", path="/admin", base_url="http://localhost:5173", kind="frontend")
    assert targets_mod._include_page_endpoint(fe, is_frontend=True) is True


def test_is_frontend_base_port(targets_mod):
    assert targets_mod.is_frontend_base("http://localhost:5173", {}) is True
    assert targets_mod.is_frontend_base("http://localhost:8080", {}) is False


def test_build_probe_targets_requires_bases(targets_mod, monkeypatch):
    monkeypatch.setattr(targets_mod, "collect_base_urls", lambda _raw: [])
    out, meta = targets_mod.build_probe_targets({})
    assert out == []
    assert meta["base_urls"] == 0


def test_dedupe_probe_bases_prefers_localhost():
    from diagnosis.replay.normalize import dedupe_probe_bases

    bases = [
        "http://host.docker.internal:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://host.docker.internal:8080",
    ]
    kept, dropped = dedupe_probe_bases(bases)
    assert kept == ["http://localhost:5173", "http://localhost:8080"]
    assert len(dropped) == 3


def test_bases_for_robots_inventory_skips_api(targets_mod):
    bases = ["http://localhost:5173", "http://localhost:8080", "http://localhost:8081"]
    robots = targets_mod.bases_for_robots_inventory(bases, {})
    assert robots == ["http://localhost:5173", "http://localhost:8081"]


def test_g35_needs_review_when_robots_missing_or_no_meta():
    scanner = _load_g35("scanner")
    needs, parts = scanner._g35_needs_review(
        {"robots_missing": 1, "robots_unreachable": 0},
        {"without_robots_directive": 0},
        None,
    )
    assert needs is True
    assert any("robots.txt missing" in p for p in parts)

    needs, parts = scanner._g35_needs_review(
        {"robots_missing": 0, "robots_unreachable": 0},
        {"without_robots_directive": 23},
        {"without_robots_directive": 0},
    )
    assert needs is True
    assert any("anon pages" in p for p in parts)

    needs, parts = scanner._g35_needs_review(
        {"robots_missing": 0, "robots_unreachable": 0},
        {"without_robots_directive": 0},
        {"without_robots_directive": 0},
    )
    assert needs is False
    assert parts == []
