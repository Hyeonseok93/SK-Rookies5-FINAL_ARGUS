"""Tests for plain-text URL/API list parsing."""

from __future__ import annotations

from pathlib import Path

from inventory.sources.txt_list import load_txt_api_list_inventory, load_txt_url_list_inventory

BASES = ["http://localhost:8080"]


def test_api_list_without_params(tmp_path: Path):
    path = tmp_path / "api.txt"
    path.write_text("GET /api/v1/health\n", encoding="utf-8")
    tree = load_txt_api_list_inventory(path, BASES)
    ep = tree.endpoints[0]
    assert ep.path == "/api/v1/health"
    assert ep.request_params == []


def test_api_list_query_in_path(tmp_path: Path):
    path = tmp_path / "api.txt"
    path.write_text(
        "GET /api/v1/accommodations/search?region=도쿄&page=0\n",
        encoding="utf-8",
    )
    tree = load_txt_api_list_inventory(path, BASES)
    ep = tree.endpoints[0]
    query = {p.name: p.sample for p in ep.request_params if p.in_ == "query"}
    assert query == {"region": "도쿄", "page": "0"}
    assert all(p.required is False for p in ep.request_params if p.in_ == "query")


def test_api_list_query_pipe_with_values(tmp_path: Path):
    path = tmp_path / "api.txt"
    path.write_text(
        "GET /api/v1/accommodations/search | region=도쿄, checkIn=2026-06-28\n",
        encoding="utf-8",
    )
    tree = load_txt_api_list_inventory(path, BASES)
    ep = tree.endpoints[0]
    query = {p.name: p.sample for p in ep.request_params if p.in_ == "query"}
    assert query == {"region": "도쿄", "checkIn": "2026-06-28"}


def test_api_list_query_pipe_names_only(tmp_path: Path):
    path = tmp_path / "api.txt"
    path.write_text("GET /api/v1/flights/search | region, departDate\n", encoding="utf-8")
    tree = load_txt_api_list_inventory(path, BASES)
    ep = tree.endpoints[0]
    query = {p.name: p.sample for p in ep.request_params if p.in_ == "query"}
    assert query == {"region": None, "departDate": None}


def test_api_list_path_param_still_required(tmp_path: Path):
    path = tmp_path / "api.txt"
    path.write_text("DELETE /api/v1/posts/{postId}\n", encoding="utf-8")
    tree = load_txt_api_list_inventory(path, BASES)
    path_params = [p for p in tree.endpoints[0].request_params if p.in_ == "path"]
    assert len(path_params) == 1
    assert path_params[0].name == "postId"
    assert path_params[0].required is True


def test_url_list_without_params(tmp_path: Path):
    path = tmp_path / "url.txt"
    path.write_text("/flight\n", encoding="utf-8")
    tree = load_txt_url_list_inventory(path, ["http://localhost:5173"])
    ep = tree.endpoints[0]
    assert ep.path == "/flight"
    assert ep.request_params == []


def test_url_list_query_in_path(tmp_path: Path):
    path = tmp_path / "url.txt"
    path.write_text("/map?lat=37.5665&lng=126.9780\n", encoding="utf-8")
    tree = load_txt_url_list_inventory(path, ["http://localhost:5173"])
    query = {p.name: p.sample for p in tree.endpoints[0].request_params if p.in_ == "query"}
    assert query == {"lat": "37.5665", "lng": "126.9780"}


def test_url_list_query_pipe(tmp_path: Path):
    path = tmp_path / "url.txt"
    path.write_text("/feed | tab=latest, sort=desc\n", encoding="utf-8")
    tree = load_txt_url_list_inventory(path, ["http://localhost:5173"])
    query = {p.name: p.sample for p in tree.endpoints[0].request_params if p.in_ == "query"}
    assert query == {"tab": "latest", "sort": "desc"}
