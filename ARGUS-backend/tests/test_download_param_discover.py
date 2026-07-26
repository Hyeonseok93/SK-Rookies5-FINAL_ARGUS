"""Tests for dynamic download endpoint parameter discovery."""

from __future__ import annotations

from pathlib import Path

from app.services import download_param_discover as discover
from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta


def _ep(**kwargs) -> Endpoint:
    defaults = {
        "method": "POST",
        "path": "/user-api/api/v1/report/integrated",
        "base_url": "http://localhost:8080",
        "tags": ["dashboard-download"],
    }
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_enrich_from_api_tree():
    ep = _ep(request_params=[])
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            Endpoint(
                method="POST",
                path="/api/v1/report/integrated",
                base_url="http://localhost:8080",
                request_params=[
                    InputParam(in_="body", name="template", sample="verification", sources=["openapi"]),
                    InputParam(in_="body", name="memberId", sample="1", sources=["openapi"]),
                ],
            ),
        ],
    )
    stats = discover.enrich_download_endpoint_params(ep, tree=tree)
    assert "api_tree" in stats["sources"]
    names = {p.name for p in ep.request_params if p.in_ == "body"}
    assert names == {"template", "memberId"}


def test_validation_error_live_probe():
    class FakeTransport:
        def request(self, method, url, headers, body, *, follow_redirects=True):
            _ = method, url, headers, body, follow_redirects
            payload = (
                b'{"errors":[{"field":"template","message":"must not be blank"},'
                b'{"field":"memberId","message":"required"}]}'
            )
            return type("R", (), {"error": None, "status": 400, "body": payload})()

    ep = _ep(request_params=[])
    stats = discover.enrich_download_endpoint_params(
        ep,
        transport=FakeTransport(),
        auth=None,
    )
    assert "live_probe" in stats["sources"]
    assert {p.name for p in ep.request_params} >= {"template", "memberId"}
