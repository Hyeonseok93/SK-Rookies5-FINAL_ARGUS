"""Tests for the 2-1 evidence capture idempotency guard and stale-dir cleanup.

Regression coverage for a bug where every capture run (auto-triggered after
each diagnosis run) re-uploaded the live malicious payload to the real
target, even for a finding that was already captured.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path


_MODULE_DIR = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-1"

# capture.py and its siblings import each other with bare names (e.g. ``from
# models import ...``) by design, so they can run standalone as a subprocess
# (see capture.py's module docstring). Other 2-2/1-4/etc. test files load
# same-named sibling files (models.py, engine.py, ...) under those same bare
# names, and whichever runs first in the shared pytest process wins the
# ``sys.modules`` cache — so we force (re)load 2-1's own copies, in
# dependency order, right before loading capture.py.
_SIBLINGS_IN_DEP_ORDER = [
    "models",
    "redaction",
    "credentials",
    "renderer",
    "replay",
    "selector",
    "engine",
]


def _force_load(name: str, directory: Path = _MODULE_DIR):
    spec = importlib.util.spec_from_file_location(name, directory / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_capture():
    if str(_MODULE_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULE_DIR))
    for name in _SIBLINGS_IN_DEP_ORDER:
        _force_load(name)
    return _force_load("capture")


_FINDING = {
    "message": "malicious upload accepted",
    "evidence": {
        "method": "POST",
        "path": "/api/v1/posts/images",
        "endpoint_id": "http://localhost:8080:POST:/api/v1/posts/images",
        "extension": "php",
        "technique": "direct_extension",
        "reason": "disallowed_extension_accepted",
        "url": "http://localhost:8080/api/v1/posts/images",
        "file_field": "images",
    },
}

_CONTEXT_KWARGS = dict(
    raw_config={},
    frontend_base_url="http://localhost:5173",
    frontend_routes=[],
    login_urls=[],
    id_field="email",
    password_field="password",
)


def _finding_output_dir(capture, tmp_path: Path) -> Path:
    case = capture.case_from_finding(
        _FINDING,
        frontend_base_url=_CONTEXT_KWARGS["frontend_base_url"],
        frontend_routes=_CONTEXT_KWARGS["frontend_routes"],
        login_urls=_CONTEXT_KWARGS["login_urls"],
        id_field=_CONTEXT_KWARGS["id_field"],
        password_field=_CONTEXT_KWARGS["password_field"],
    )
    return tmp_path / case.finding_id


def test_cached_artifacts_returns_none_when_no_manifest(tmp_path):
    capture = _load_capture()
    assert capture._cached_artifacts(tmp_path / "missing") is None


def test_cached_artifacts_returns_none_when_replay_not_performed(tmp_path):
    capture = _load_capture()
    output_dir = tmp_path / "2-1-abc"
    output_dir.mkdir()
    (output_dir / "manifest.json").write_text(
        json.dumps({"artifacts": [], "metadata": {"replay": {"performed": False}}}),
        encoding="utf-8",
    )
    assert capture._cached_artifacts(output_dir) is None


def test_cached_artifacts_returns_artifacts_when_replay_performed(tmp_path):
    capture = _load_capture()
    output_dir = tmp_path / "2-1-abc"
    output_dir.mkdir()
    expected = [{"kind": "attack_evidence", "path": "05_attack_evidence.png"}]
    (output_dir / "manifest.json").write_text(
        json.dumps({"artifacts": expected, "metadata": {"replay": {"performed": True}}}),
        encoding="utf-8",
    )
    assert capture._cached_artifacts(output_dir) == expected


def test_capture_finding_skips_live_reupload_when_already_captured(tmp_path, monkeypatch):
    capture = _load_capture()
    output_dir = _finding_output_dir(capture, tmp_path)
    output_dir.mkdir(parents=True)
    cached_artifacts = [{"kind": "attack_evidence", "path": str(output_dir / "05_attack_evidence.png")}]
    (output_dir / "manifest.json").write_text(
        json.dumps({"artifacts": cached_artifacts, "metadata": {"replay": {"performed": True}}}),
        encoding="utf-8",
    )

    calls = {"replay": 0, "capture": 0}
    monkeypatch.setattr(capture, "replay_case", lambda case, **kw: calls.__setitem__("replay", calls["replay"] + 1) or case)
    monkeypatch.setattr(capture, "capture_case", lambda case, out_dir: calls.__setitem__("capture", calls["capture"] + 1) or [])

    artifacts = capture.capture_finding(_FINDING, tmp_path, data_dir=tmp_path, **_CONTEXT_KWARGS)

    assert calls == {"replay": 0, "capture": 0}
    assert artifacts == cached_artifacts


def test_capture_finding_force_replay_bypasses_cache(tmp_path, monkeypatch):
    capture = _load_capture()
    output_dir = _finding_output_dir(capture, tmp_path)
    output_dir.mkdir(parents=True)
    (output_dir / "manifest.json").write_text(
        json.dumps({"artifacts": [{"kind": "old", "path": "old.png"}], "metadata": {"replay": {"performed": True}}}),
        encoding="utf-8",
    )

    calls = {"replay": 0, "capture": 0}

    def fake_replay(case, **kw):
        calls["replay"] += 1
        return case

    def fake_capture_case(case, out_dir):
        calls["capture"] += 1
        return []

    monkeypatch.setattr(capture, "replay_case", fake_replay)
    monkeypatch.setattr(capture, "capture_case", fake_capture_case)

    capture.capture_finding(_FINDING, tmp_path, data_dir=tmp_path, force_replay=True, **_CONTEXT_KWARGS)

    assert calls == {"replay": 1, "capture": 1}


def test_cleanup_stale_dirs_respects_grace_period_and_keep_set(tmp_path):
    capture = _load_capture()

    keep_dir = tmp_path / "2-1-keepme"
    keep_dir.mkdir()
    old_dir = tmp_path / "2-1-old"
    old_dir.mkdir()
    fresh_dir = tmp_path / "2-1-fresh"
    fresh_dir.mkdir()

    old_time = time.time() - (capture._STALE_DIR_GRACE_SECONDS + 30)
    os.utime(old_dir, (old_time, old_time))

    capture._cleanup_stale_dirs(tmp_path, keep={"2-1-keepme"})

    assert keep_dir.is_dir()
    assert not old_dir.exists()
    assert fresh_dir.is_dir()
