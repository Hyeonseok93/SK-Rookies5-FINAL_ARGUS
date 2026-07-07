"""Docker probe-host rewriting for diagnosis module 1-6.

1-6 used to send requests to whatever base URL the dashboard/inventory recorded
(typically ``http://localhost:8080``). Inside a container that resolves to the
container itself, so the target was unreachable. Unlike the other probe modules
(1-5, 3-5, 5-2, 7-2) it did not route through ``inventory.net``'s
``ARGUS_PROBE_HOST`` rewrite. These tests lock in that it now does — and that the
rewrite stays a no-op for native (non-Docker) runs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_MODULES = Path(__file__).resolve().parents[1] / "diagnosis" / "modules"


def _load_g16():
    g16_dir = _MODULES / "1-6"
    if str(g16_dir) not in sys.path:
        sys.path.insert(0, str(g16_dir))
    import g16_inventory  # noqa: E402
    import g16_targets  # noqa: E402

    return g16_targets, g16_inventory


def _write_api_tree(data_dir: Path, endpoints: list[dict]) -> None:
    (data_dir / "api-tree-ready.json").write_text(
        json.dumps({"endpoints": endpoints}), encoding="utf-8"
    )


def test_g16_target_and_spec_rewritten_under_docker(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    g16_targets, _ = _load_g16()
    _write_api_tree(
        tmp_path,
        [
            {"method": "GET", "path": "/api/v1/members/me", "base_url": "http://localhost:8080", "kind": "api"},
            {"method": "POST", "path": "/api/v1/admin/x", "base_url": "http://localhost:8081", "kind": "api"},
        ],
    )
    (tmp_path / "base-urls.json").write_text(
        json.dumps({"urls": [{"url": "http://localhost:8080"}]}), encoding="utf-8"
    )

    et = g16_targets.resolve_engine_target(
        {}, {"targets": [{"base_url": "http://localhost:8080"}]}, _MODULES / "1-6", data_dir=tmp_path
    )
    assert et.target == "http://host.docker.internal:8080"

    spec = json.loads(Path(et.api_spec).read_text(encoding="utf-8"))
    assert spec["servers"][0]["url"] == "http://host.docker.internal:8080"
    bases = spec["x-argus-generation-stats"]["base_urls"]
    assert bases == ["http://host.docker.internal:8080", "http://host.docker.internal:8081"]
    assert all("localhost" not in b for b in bases)


def test_g16_login_override_rewritten_under_docker(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PROBE_HOST", "host.docker.internal")
    _, g16_inventory = _load_g16()
    (tmp_path / "login-endpoints.json").write_text(
        json.dumps({"endpoints": [{"kind": "api", "url": "http://localhost:8080/api/v1/auth/login"}]}),
        encoding="utf-8",
    )
    override = g16_inventory.login_override(tmp_path, "http://host.docker.internal:8080")
    assert override["login_target"] == "http://host.docker.internal:8080"
    assert override["login_path"] == "/api/v1/auth/login"


def test_g16_target_unchanged_without_docker_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_PROBE_HOST", raising=False)
    g16_targets, _ = _load_g16()
    _write_api_tree(
        tmp_path,
        [{"method": "GET", "path": "/api/v1/members/me", "base_url": "http://localhost:8080", "kind": "api"}],
    )
    (tmp_path / "base-urls.json").write_text(
        json.dumps({"urls": [{"url": "http://localhost:8080"}]}), encoding="utf-8"
    )
    et = g16_targets.resolve_engine_target(
        {}, {"targets": [{"base_url": "http://localhost:8080"}]}, _MODULES / "1-6", data_dir=tmp_path
    )
    assert et.target == "http://localhost:8080"
