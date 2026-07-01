"""Tests for 7-3 probe target selection."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "7-3"
_DATA = Path(__file__).resolve().parent.parent / "data"


def _patch_dashboard(monkeypatch, bases: list[str]) -> None:
    from diagnosis.replay import normalize as norm

    monkeypatch.setattr(norm, "load_dashboard_base_urls", lambda: bases)


def _load_targets():
    mod_name = "diag_g73_targets_test2"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "targets.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tree(*endpoints: Endpoint) -> ApiTree:
    return ApiTree(meta=InventoryMeta(app_name="test"), endpoints=list(endpoints))


def test_base_only_three_bases(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(
        monkeypatch,
        ["http://localhost:5173", "http://localhost:8080", "http://localhost:8081"],
    )
    urls, meta = targets.build_probe_urls({}, probe_mode="base_only")
    assert meta["probe_mode"] == "base_only"
    assert len(urls) == 3
    assert all(t["source"] == "base" for t in urls)


def test_sample_limits_per_base(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    eps = [
        Endpoint(method="GET", path=f"/api/{i}", base_url="http://localhost:8080")
        for i in range(30)
    ]
    eps.insert(0, Endpoint(method="GET", path="/", base_url="http://localhost:8080"))
    tree = _tree(*eps)

    monkeypatch.setattr(targets, "load_api_tree", lambda _d: tree)
    urls, meta = targets.build_probe_urls(
        {},
        data_dir=_DATA,
        probe_mode="sample",
        sample_size=5,
    )
    assert meta["inventory_selected"] <= 5
    assert len(urls) >= 5
    assert any(t["source"] == "inventory" for t in urls)


def test_full_uses_all_inventory_paths(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    eps = [
        Endpoint(method="GET", path="/", base_url="http://localhost:8080"),
        Endpoint(method="GET", path="/health", base_url="http://localhost:8080"),
        Endpoint(method="POST", path="/api/foo", base_url="http://localhost:8080"),
    ]
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: _tree(*eps))
    urls, meta = targets.build_probe_urls({}, data_dir=_DATA, probe_mode="full")
    assert meta["inventory_selected"] == 2
    assert len(urls) == 3


def test_inventory_fallback_without_tree(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["http://localhost:8080"])
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: None)
    urls, meta = targets.build_probe_urls({}, data_dir=_DATA, probe_mode="full")
    assert meta["inventory_fallback"] is True
    assert len(urls) == 1


def test_frontend_base_url_skipped_when_dashboard_configured(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["https://onde.click", "https://rookies.onde.click"])
    urls, meta = targets.build_probe_urls(
        {
            "inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}},
            "targets": [
                {"base_url": "http://localhost:8080"},
                {"base_url": "http://host.docker.internal:8081"},
            ],
        },
        probe_mode="base_only",
    )
    base_urls = {t["base_url"] for t in urls}
    assert base_urls == {"https://onde.click", "https://rookies.onde.click"}
    assert meta["base_urls"] == 2


def test_frontend_base_url_kept_when_on_dashboard(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["http://localhost:5173"])
    urls, meta = targets.build_probe_urls(
        {"inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}}},
        probe_mode="base_only",
    )
    assert meta["base_urls"] == 1
    assert urls[0]["base_url"] == "http://localhost:5173"


def test_frontend_base_url_when_dashboard_empty(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, [])
    urls, meta = targets.build_probe_urls(
        {"inventory": {"markdown": {"frontend_base_url": "http://localhost:5173"}}},
        probe_mode="base_only",
    )
    assert meta["base_urls"] == 1
    assert urls[0]["base_url"] == "http://localhost:5173"


def test_collapse_header_findings():
    scanner_path = _MODULE_DIR / "scanner.py"
    spec = importlib.util.spec_from_file_location("diag_g73_scanner_test", scanner_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["diag_g73_scanner_test"] = mod
    spec.loader.exec_module(mod)

    from diagnosis.result import DiagnosisFinding

    items = [
        DiagnosisFinding(
            severity="medium",
            message="a",
            evidence={
                "header": "server",
                "header_value": "nginx/1.0",
                "base_url": "http://localhost:5173",
                "url": "http://localhost:5173/",
                "reason": "version_disclosed",
            },
        ),
        DiagnosisFinding(
            severity="medium",
            message="b",
            evidence={
                "header": "server",
                "header_value": "nginx/1.0",
                "base_url": "http://localhost:5173",
                "url": "http://localhost:5173/foo",
                "reason": "version_disclosed",
            },
        ),
    ]
    collapsed, stats = mod._collapse_header_findings(items)
    assert len(collapsed) == 1
    assert collapsed[0].evidence["affected_count"] == 2
    assert stats["raw_issues"] == 2
    assert stats["collapsed_issues"] == 1
