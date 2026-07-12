from __future__ import annotations

import json

import yaml

from app.services import base_urls_service as svc


def test_save_base_urls_syncs_config_files(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    config = tmp_path / "config.yaml"
    docker_config = tmp_path / "config.docker.yaml"
    initial = {
        "app_name": "onde-pilot",
        "targets": [{"name": "old", "base_url": "http://localhost:9999"}],
        "inventory": {
            "markdown": {"enabled": True, "frontend_base_url": "http://localhost:9998"},
            "openapi": {"enabled": False, "base_url": "http://localhost:9999"},
        },
        "diagnosis_1_5": {"probe_mode": "full"},
    }
    config.write_text(yaml.safe_dump(initial, sort_keys=False), encoding="utf-8")
    docker_config.write_text(yaml.safe_dump(initial, sort_keys=False), encoding="utf-8")

    monkeypatch.setattr(svc, "DATA_DIR", data_dir)
    monkeypatch.setattr(svc, "BASE_URLS_PATH", data_dir / "base-urls.json")
    monkeypatch.setattr(svc, "CONFIG_PATHS", (config, docker_config))

    saved = svc.save_base_urls(
        [
            {"id": "api", "url": "http://localhost:8080", "kind": "api"},
            {"id": "front", "url": "http://localhost:5173/", "kind": "frontend"},
        ]
    )

    assert saved["urls"] == [
        {"id": "api", "url": "http://localhost:8080", "kind": "api"},
        {"id": "front", "url": "http://localhost:5173", "kind": "frontend"},
    ]
    assert json.loads((data_dir / "base-urls.json").read_text(encoding="utf-8")) == saved

    native = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert native["targets"] == [{"name": "api", "base_url": "http://localhost:8080"}]
    assert native["inventory"]["markdown"]["frontend_base_url"] == "http://localhost:5173"
    assert native["inventory"]["openapi"]["base_url"] == "http://localhost:8080"
    assert native["diagnosis_1_5"] == {"probe_mode": "full"}

    docker = yaml.safe_load(docker_config.read_text(encoding="utf-8"))
    assert docker["targets"] == [
        {"name": "api", "base_url": "http://host.docker.internal:8080"}
    ]
    assert docker["inventory"]["markdown"]["frontend_base_url"] == "http://localhost:5173"
    assert docker["inventory"]["openapi"]["base_url"] == "http://host.docker.internal:8080"


def test_base_url_roles_do_not_depend_on_port_numbers(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump({"targets": [], "inventory": {"markdown": {}, "openapi": {}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(svc, "DATA_DIR", data_dir)
    monkeypatch.setattr(svc, "BASE_URLS_PATH", data_dir / "base-urls.json")
    monkeypatch.setattr(svc, "CONFIG_PATHS", (config,))

    svc.save_base_urls(
        [
            {"id": "front", "url": "http://example.test:8080", "kind": "frontend"},
            {"id": "api", "url": "http://api.test:3000", "kind": "api"},
        ]
    )

    api, frontend = svc.resolved_base_urls_by_kind()
    assert api == ["http://api.test:3000"]
    assert frontend == ["http://example.test:8080"]
