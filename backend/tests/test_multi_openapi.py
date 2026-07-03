from __future__ import annotations

import json
from pathlib import Path

from app.services.inventory_service import build_inventory_from_dict, persist_inventory
from inventory.load import find_openapi_specs


def _spec(path: Path, server: str, route: str) -> None:
    path.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "servers": [{"url": server}],
                "paths": {route: {"get": {"responses": {"200": {"description": "ok"}}}}},
            }
        ),
        encoding="utf-8",
    )


def test_zero_openapi_files_reports_missing():
    tree = build_inventory_from_dict({}, openapi=True, openapi_paths=[])
    assert tree.endpoints == []
    assert "openapi" in tree.meta.sources_missing


def test_one_openapi_file_keeps_original_filename_source(tmp_path: Path):
    spec = tmp_path / "stored.json"
    _spec(spec, "http://service-a:8080", "/a")
    tree = build_inventory_from_dict(
        {},
        openapi=True,
        openapi_paths=[spec],
        openapi_source_names=["user-service-openapi.json"],
    )
    assert len(tree.endpoints) == 1
    assert tree.endpoints[0].base_url == "http://service-a:8080"
    assert tree.endpoints[0].sources == ["openapi:user-service-openapi"]


def test_three_openapi_files_merge_and_all_export_to_zap(tmp_path: Path):
    specs = [tmp_path / f"stored-{index}.json" for index in range(3)]
    names = ["alpha.json", "beta.yaml", "gamma-openapi.json"]
    _spec(specs[0], "http://shared:8080", "/shared")
    _spec(specs[1], "http://shared:8080", "/shared")
    _spec(specs[2], "http://gamma:8090", "/gamma")

    tree = build_inventory_from_dict(
        {}, openapi=True, openapi_paths=specs, openapi_source_names=names
    )
    assert len(tree.endpoints) == 2
    shared = next(endpoint for endpoint in tree.endpoints if endpoint.path == "/shared")
    assert shared.sources == ["openapi:alpha", "openapi:beta"]

    data_dir = tmp_path / "data"
    persist_inventory(tree, data_dir, specs)
    bundle = json.loads((data_dir / "zap-inventory-bundle.json").read_text(encoding="utf-8"))
    assert len(bundle["openapi_imports"]) == 3
    assert find_openapi_specs(data_dir) == [path.resolve() for path in specs]
