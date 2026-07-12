"""Tests for 2-1 upload-target base_url resolution.

Regression test for a bug where ``_from_inventory`` compared each endpoint's
recorded base_url against a set built from the very same endpoints (always
true), so the dashboard/config-collected ``bases`` fallback never applied and
stale inventory base_urls were used verbatim.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "2-1"
_DATA = Path(__file__).resolve().parents[1] / "data"


def _load_targets():
    mod_name = "diag_g21_targets_test"
    spec = importlib.util.spec_from_file_location(mod_name, _MODULE_DIR / "targets.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _patch_dashboard(monkeypatch, bases: list[str]) -> None:
    from diagnosis.replay import normalize as norm

    monkeypatch.setattr(norm, "load_dashboard_base_urls", lambda: bases)


def _upload_endpoint(path: str, base_url: str) -> Endpoint:
    return Endpoint(
        method="POST",
        path=path,
        base_url=base_url,
        request_params=[
            InputParam(in_="body", name="images", type="array", sample="a.jpg"),
        ],
        kind="api",
    )


def test_endpoint_matching_known_base_uses_only_that_base(monkeypatch):
    targets = _load_targets()
    _patch_dashboard(monkeypatch, ["http://svc-a.internal:8080", "http://svc-b.internal:8080"])

    ep = _upload_endpoint("/api/v1/posts/images", "http://svc-a.internal:8080")
    tree = ApiTree(meta=InventoryMeta(app_name="test"), endpoints=[ep])
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: tree)

    out, _meta = targets.build_upload_targets({}, data_dir=_DATA, default_allowed_extensions=["jpg"])

    matches = [t for t in out if t.path == "/api/v1/posts/images"]
    assert len(matches) == 1
    assert matches[0].base_url == "http://svc-a.internal:8080"


def test_endpoint_with_stale_base_falls_back_to_all_known_bases(monkeypatch):
    targets = _load_targets()
    # Distinct ports so dedupe_probe_bases (which collapses same-port
    # localhost/127.0.0.1/host.docker.internal aliases) keeps both bases —
    # e.g. a main API base plus a separately-mapped admin base.
    _patch_dashboard(monkeypatch, ["http://svc-a.internal:8080", "http://svc-a.internal:8081"])

    # This endpoint's recorded base_url is neither configured base — e.g. captured
    # from an old dev host. The config override should still apply to it.
    ep = _upload_endpoint("/api/v1/cars/images", "http://stale-dev-host:9999")
    tree = ApiTree(meta=InventoryMeta(app_name="test"), endpoints=[ep])
    monkeypatch.setattr(targets, "load_api_tree", lambda _d: tree)

    out, _meta = targets.build_upload_targets({}, data_dir=_DATA, default_allowed_extensions=["jpg"])

    matches = [t for t in out if t.path == "/api/v1/cars/images"]
    base_urls = {t.base_url for t in matches}
    assert base_urls == {"http://svc-a.internal:8080", "http://svc-a.internal:8081"}
    assert "http://stale-dev-host:9999" not in base_urls
