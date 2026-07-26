from __future__ import annotations

import json
from pathlib import Path

from app.services.inventory_service import build_inventory_from_dict


def test_api_and_frontend_sources_use_only_their_role_bases(tmp_path: Path):
    api_list = tmp_path / "api-list.txt"
    url_list = tmp_path / "url-list.txt"
    spec = tmp_path / "openapi.json"
    api_list.write_text("POST /api/auth/login\n", encoding="utf-8")
    url_list.write_text("/login\n", encoding="utf-8")
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {
                    "/api/auth/login": {
                        "post": {"responses": {"200": {"description": "ok"}}}
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    tree = build_inventory_from_dict(
        {},
        api_list=True,
        url_list=True,
        openapi=True,
        api_list_path=api_list,
        url_list_path=url_list,
        openapi_paths=[spec],
        api_base_urls=["http://api.example:3000"],
        frontend_base_urls=["http://web.example:8080"],
    )

    login_api = next(ep for ep in tree.endpoints if ep.kind == "api")
    login_page = next(ep for ep in tree.endpoints if ep.kind == "frontend")
    assert login_api.base_url == "http://api.example:3000"
    assert login_api.sources == ["api_list", "openapi:openapi"]
    assert login_page.base_url == "http://web.example:8080"
    assert all(ep.base_url != "http://web.example:8080" for ep in tree.endpoints if ep.kind == "api")
