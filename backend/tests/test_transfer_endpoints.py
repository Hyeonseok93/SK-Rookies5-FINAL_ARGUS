"""Tests for dashboard upload/download endpoint storage."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from app.services import transfer_endpoints_service as svc


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(svc, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        svc,
        "_PATHS",
        {
            "upload": tmp_path / "upload-endpoints.json",
            "download": tmp_path / "download-endpoints.json",
        },
    )
    return tmp_path


def test_save_and_load_upload_endpoints(data_dir):
    saved = svc.save_transfer_endpoints(
        "upload",
        [{"id": "a", "url": "/api/v1/upload", "method": "POST"}],
    )
    assert len(saved["endpoints"]) == 1
    assert saved["endpoints"][0]["method"] == "POST"
    loaded = svc.load_transfer_endpoints("upload")
    assert loaded["endpoints"][0]["url"] == "/api/v1/upload"


def test_download_defaults_to_get(data_dir):
    saved = svc.save_transfer_endpoints("download", [{"id": "b", "url": "/api/export"}])
    assert saved["endpoints"][0]["method"] == "GET"


def test_dashboard_transfer_entries_resolves_path(data_dir, monkeypatch):
    svc.save_transfer_endpoints("download", [{"id": "1", "url": "/api/v1/files/{id}"}])
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    rows = svc.dashboard_transfer_entries("download", {})
    assert len(rows) == 1
    assert rows[0]["path"] == "/api/v1/files/{id}"
    assert rows[0]["method"] == "GET"


def test_merge_dashboard_download_candidates(data_dir, monkeypatch):
    mod_path = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-2" / "candidates.py"
    spec = importlib.util.spec_from_file_location("g22_candidates_test", mod_path)
    assert spec and spec.loader
    candidates_mod = importlib.util.module_from_spec(spec)
    sys.modules["g22_candidates_test"] = candidates_mod
    spec.loader.exec_module(candidates_mod)

    svc.save_transfer_endpoints("download", [{"id": "1", "url": "/api/manual-download"}])
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    merged = candidates_mod.merge_dashboard_download_candidates([], {})
    assert len(merged) == 1
    assert merged[0].path == "/api/manual-download"
    assert "dashboard-download" in merged[0].tags


def test_select_dashboard_download_only(data_dir, monkeypatch):
    mod_path = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-2" / "candidates.py"
    spec = importlib.util.spec_from_file_location("g22_candidates_only_test", mod_path)
    assert spec and spec.loader
    candidates_mod = importlib.util.module_from_spec(spec)
    sys.modules["g22_candidates_only_test"] = candidates_mod
    spec.loader.exec_module(candidates_mod)

    svc.save_transfer_endpoints("download", [{"id": "1", "url": "/api/export/report"}])
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    rows, mode = candidates_mod.select_dashboard_download_candidates_only({})
    assert mode == "dashboard_download_only"
    assert len(rows) == 1
    assert rows[0].path == "/api/export/report"


def test_download_inventory_parses_query_params(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    svc.save_transfer_endpoints(
        "download",
        [{"id": "1", "url": "/api/v1/files/download?file=report.pdf&userId=42"}],
    )
    eps = svc.dashboard_endpoints_as_inventory("download", {})
    assert len(eps) == 1
    params = {(p.in_, p.name): p.sample for p in eps[0].request_params}
    assert params[("query", "file")] == "report.pdf"
    assert params[("query", "userId")] == "42"
    assert eps[0].path == "/api/v1/files/download"


def test_download_inventory_parses_path_template(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    svc.save_transfer_endpoints("download", [{"id": "1", "url": "/api/v1/files/{fileId}"}])
    eps = svc.dashboard_endpoints_as_inventory("download", {})
    path_params = [p for p in eps[0].request_params if p.in_ == "path"]
    assert len(path_params) == 1
    assert path_params[0].name == "fileId"


def test_download_inventory_post_without_url_has_no_hardcoded_params(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    svc.save_transfer_endpoints(
        "download",
        [{"id": "1", "url": "/api/v1/report/integrated", "method": "POST"}],
    )
    eps = svc.dashboard_endpoints_as_inventory("download", {})
    assert len(eps) == 1
    assert eps[0].path == "/api/v1/report/integrated"
    assert eps[0].request_params == []


def test_download_relative_path_expands_all_dashboard_bases(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: [
            "http://localhost:5173",
            "http://localhost:8080",
            "http://localhost:8081",
        ],
    )
    svc.save_transfer_endpoints(
        "download",
        [{"id": "1", "url": "/api/v1/report/integrated", "method": "POST"}],
    )
    rows = svc.dashboard_transfer_entries("download", {})
    assert len(rows) == 3
    assert {row["base_url"] for row in rows} == {
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:8081",
    }
    assert all(row["path"] == "/api/v1/report/integrated" for row in rows)
    for row in rows:
        assert row["url"].endswith("/api/v1/report/integrated")
        assert "/user-api" not in row["url"]


def test_download_registration_preserves_gateway_prefix(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    svc.save_transfer_endpoints(
        "download",
        [{"id": "1", "url": "/user-api/api/v1/report/integrated", "method": "POST"}],
    )
    eps = svc.dashboard_endpoints_as_inventory("download", {})
    assert len(eps) == 1
    assert eps[0].path == "/user-api/api/v1/report/integrated"


def test_download_inventory_infers_path_sample_from_resolved_url(data_dir, monkeypatch):
    monkeypatch.setattr(
        "app.services.transfer_endpoints_service.collect_probe_base_urls",
        lambda _raw: ["http://localhost:8080"],
    )
    svc.save_transfer_endpoints("download", [{"id": "1", "url": "/api/v1/files/99"}])
    eps = svc.dashboard_endpoints_as_inventory("download", {})
    assert eps[0].request_params == []
