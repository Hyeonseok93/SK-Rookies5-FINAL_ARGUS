from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_selector():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-2" / "selector.py"
    spec = importlib.util.spec_from_file_location("g22_selector_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_select_representatives_prefers_path_traversal_leak():
    selector = _load_selector()
    findings = [
        {
            "severity": "medium",
            "message": "input validation",
            "evidence": {
                "rule_id": "2-2-input-validation",
                "method": "GET",
                "path": "/api/file",
                "param": "name",
                "payload": "../etc/passwd",
                "url": "http://localhost:8080/api/file?name=../etc/passwd",
            },
        },
        {
            "severity": "high",
            "message": "path traversal leak",
            "evidence": {
                "rule_id": "2-2-path-traversal",
                "method": "GET",
                "path": "/api/file",
                "param": "name",
                "payload": "../etc/passwd",
                "url": "http://localhost:8080/api/file?name=../etc/passwd",
                "payload_leak_confirmed": True,
                "trigger": "payload_target_leak_confirmed",
            },
        },
    ]

    selected = selector.select_representatives(findings, limit=1)

    assert len(selected) == 1
    assert selected[0]["evidence"]["rule_id"] == "2-2-path-traversal"


def test_design_findings_are_not_capturable():
    selector = _load_selector()
    finding = {
        "severity": "medium",
        "evidence": {"rule_id": "2-2-design", "path": "/download"},
    }
    assert selector.is_capturable(finding) is False
