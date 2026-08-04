from __future__ import annotations

import json

from app.services import base_urls_service as svc
from app.services.base_urls_service import apply_base_urls_to_raw_config


def test_save_base_urls_persists_workspace_json(tmp_path):
    data_dir = tmp_path / "data"
    saved = svc.save_base_urls(
        data_dir,
        [
            {"id": "api", "url": "http://localhost:8080", "kind": "api"},
            {"id": "front", "url": "http://localhost:5173/", "kind": "frontend"},
        ],
    )

    assert saved["urls"] == [
        {"id": "api", "url": "http://localhost:8080", "kind": "api"},
        {"id": "front", "url": "http://localhost:5173", "kind": "frontend"},
    ]
    assert json.loads((data_dir / "base-urls.json").read_text(encoding="utf-8")) == saved


def test_apply_base_urls_to_raw_config_in_memory():
    raw = {
        "app_name": "argus",
        "targets": [{"name": "old", "base_url": "http://localhost:9999"}],
        "inventory": {
            "markdown": {"enabled": True, "frontend_base_url": "http://localhost:9998"},
            "openapi": {"enabled": False, "base_url": "http://localhost:9999"},
        },
        "diagnosis_1_5": {"probe_mode": "full"},
    }
    patched = apply_base_urls_to_raw_config(
        raw,
        [
            {"id": "api", "url": "http://localhost:8080", "kind": "api"},
            {"id": "front", "url": "http://localhost:5173", "kind": "frontend"},
        ],
    )
    assert patched["targets"] == [{"name": "api", "base_url": "http://localhost:8080"}]
    assert patched["inventory"]["markdown"]["frontend_base_url"] == "http://localhost:5173"
    assert patched["inventory"]["openapi"]["base_url"] == "http://localhost:8080"
    assert patched["diagnosis_1_5"] == {"probe_mode": "full"}


def test_base_url_roles_do_not_depend_on_port_numbers(tmp_path):
    data_dir = tmp_path / "data"
    svc.save_base_urls(
        data_dir,
        [
            {"id": "front", "url": "http://example.test:8080", "kind": "frontend"},
            {"id": "api", "url": "http://api.test:3000", "kind": "api"},
        ],
    )

    api, frontend = svc.resolved_base_urls_by_kind(data_dir)
    assert api == ["http://api.test:3000"]
    assert frontend == ["http://example.test:8080"]
