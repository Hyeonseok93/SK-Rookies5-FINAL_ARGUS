"""Tests for api-tree loader preference."""

from __future__ import annotations

from inventory.load import load_param_discovery_api_tree
from inventory.schema import ApiTree, Endpoint, InventoryMeta


def test_param_discovery_prefers_verified(tmp_path):
    ready = ApiTree(meta=InventoryMeta(), endpoints=[Endpoint(method="GET", path="/a", base_url="http://x")])
    verified = ApiTree(meta=InventoryMeta(), endpoints=[Endpoint(method="GET", path="/b", base_url="http://x")])
    ready.save(tmp_path / "api-tree-ready.json")
    verified.save(tmp_path / "api-tree-verified.json")

    tree, source = load_param_discovery_api_tree(tmp_path)
    assert source == "api-tree-verified.json"
    assert tree is not None
    assert tree.endpoints[0].path == "/b"


def test_param_discovery_falls_back_to_ready(tmp_path):
    ready = ApiTree(meta=InventoryMeta(), endpoints=[Endpoint(method="GET", path="/a", base_url="http://x")])
    ready.save(tmp_path / "api-tree-ready.json")

    tree, source = load_param_discovery_api_tree(tmp_path)
    assert source == "api-tree-ready.json"
    assert tree is not None
    assert tree.endpoints[0].path == "/a"


def test_param_discovery_skips_legacy_api_tree_json(tmp_path):
    legacy = ApiTree(meta=InventoryMeta(), endpoints=[Endpoint(method="GET", path="/legacy", base_url="http://x")])
    legacy.save(tmp_path / "api-tree.json")

    tree, source = load_param_discovery_api_tree(tmp_path)
    assert tree is None
    assert source is None
