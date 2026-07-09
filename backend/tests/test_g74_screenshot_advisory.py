from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "screenshot"
        / "modules"
        / "7-4"
        / "advisory.py"
    )
    spec = importlib.util.spec_from_file_location("g74_screenshot_advisory", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


advisory = _load_module()


def _row(advisory_id: str, **overrides):
    row = {
        "advisory_id": advisory_id,
        "installed_version_affected": True,
        "operating_conditions": "likely",
        "severity": "high",
        "cvss_version": "3.1",
        "cvss_score": 7.5,
        "epss": 0.01,
        "public_poc": False,
        "remote": True,
        "unauthenticated": True,
    }
    row.update(overrides)
    return row


def test_prefers_applicable_operating_conditions_before_score():
    selected = advisory.select_representative(
        [
            _row("GHSA-high-score", cvss_score=9.8, operating_conditions="unconfirmed"),
            _row("GHSA-applicable", cvss_score=7.5, operating_conditions="confirmed"),
        ]
    )
    assert selected["advisory_id"] == "GHSA-applicable"


def test_compares_scores_only_for_same_cvss_version():
    selected = advisory.select_representative(
        [
            _row("GHSA-v4", cvss_version="4.0", cvss_score=7.2, epss=0.02),
            _row("GHSA-v3", cvss_version="3.1", cvss_score=9.8, epss=0.01),
        ]
    )
    assert selected["advisory_id"] == "GHSA-v4"


def test_uses_ghsa_id_as_final_tie_breaker():
    selected = advisory.select_representative([_row("GHSA-b"), _row("GHSA-a")])
    assert selected["advisory_id"] == "GHSA-a"
