"""Tests for shared inventory loaders and network helpers."""

from __future__ import annotations

import json
from pathlib import Path

from inventory.load import find_openapi_spec, load_best_api_tree, load_cached_tree
from inventory.net import probe_base_url, probe_url
from inventory.schema import ApiTree, InventoryMeta
from inventory.upload_retention import prune_upload_batches


def test_load_best_api_tree_prefers_verified(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    ready = ApiTree(meta=InventoryMeta(), endpoints=[])
    ready.save(data_dir / "api-tree-ready.json")
    verified = ApiTree(meta=InventoryMeta(app_name="verified"), endpoints=[])
    verified.save(data_dir / "api-tree-verified.json")

    tree = load_best_api_tree(data_dir)
    assert tree is not None
    assert tree.meta.app_name == "verified"


def test_load_cached_tree_verified_only(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    ready = ApiTree(meta=InventoryMeta(), endpoints=[])
    ready.save(data_dir / "api-tree-ready.json")

    assert load_cached_tree(data_dir, inventory="verified") is None
    assert load_cached_tree(data_dir, inventory="ready") is not None


def test_find_openapi_spec_from_bundle(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    spec = data_dir / "uploads" / "batch-1" / "openapi.json"
    spec.parent.mkdir(parents=True)
    spec.write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")
    bundle = {
        "openapi_imports": [{"type": "openapi", "file": str(spec)}],
    }
    (data_dir / "zap-inventory-bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

    found = find_openapi_spec(data_dir)
    assert found == spec


def test_probe_url_rewrites_localhost_when_env(monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    out = probe_url("http://localhost:8080/api/v1/foo?x=1")
    assert out == "http://host.docker.internal:8080/api/v1/foo?x=1"


def test_probe_base_url_keeps_localhost_without_env(monkeypatch):
    monkeypatch.delenv("ARGUS_PROBE_HOST", raising=False)
    assert probe_base_url("http://localhost:8080") == "http://localhost:8080"


def test_prune_upload_batches_keeps_newest_five(tmp_path: Path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    for i in range(7):
        batch = uploads / f"batch-{i}"
        batch.mkdir()
        (batch / "openapi.json").write_text("{}", encoding="utf-8")
        ts = 1_700_000_000 + i
        import os

        os.utime(batch, (ts, ts))

    removed = prune_upload_batches(uploads, keep_max=5)
    assert set(removed) == {"batch-0", "batch-1"}
    remaining = sorted(p.name for p in uploads.iterdir() if p.is_dir())
    assert remaining == [f"batch-{i}" for i in range(2, 7)]


def test_prune_upload_batches_noop_when_under_limit(tmp_path: Path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    (uploads / "only").mkdir()
    assert prune_upload_batches(uploads, keep_max=5) == []
