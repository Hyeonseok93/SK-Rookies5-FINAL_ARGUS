from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_selector():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "1-5" / "selector.py"
    spec = importlib.util.spec_from_file_location("g15_selector_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_stats_finding_is_not_capturable():
    selector = _load_selector()
    finding = {
        "severity": "info",
        "message": "1-5 scan statistics",
        "evidence": {"stats": {}},
    }
    assert selector.is_capturable(finding) is False


def test_reflected_finding_without_navigable_url_is_not_capturable():
    selector = _load_selector()
    finding = {
        "severity": "low",
        "evidence": {
            "rule_id": "1-5-reflected-probe",
            "location": "REFLECTED_VALUE:https://argus-unvalidated-redirect-poc.invalid/",
        },
    }
    assert selector.is_capturable(finding) is False


def test_select_representatives_dedupes_by_rule_path_param_and_prefers_higher_severity():
    selector = _load_selector()
    findings = [
        {
            "severity": "low",
            "message": "reflected only",
            "evidence": {
                "rule_id": "1-5-reflected-xss-probe",
                "url": "http://localhost:8080/api/v1/posts/1/comments?memberId=1",
                "test_url": "http://localhost:8080/api/v1/posts/1/comments?memberId=1#content",
                "param_name": "content",
                "method": "POST",
                "confirmed_redirect": False,
            },
        },
        {
            "severity": "high",
            "message": "confirmed open redirect",
            "evidence": {
                "rule_id": "1-5-open-redirect",
                "test_url": "http://localhost:8080/redirect?next=https://evil.example",
                "baseline_url": "http://localhost:8080/redirect?next=/home",
                "param_name": "next",
                "method": "GET",
                "confirmed_redirect": True,
            },
        },
        {
            "severity": "high",
            "message": "CORS misconfiguration",
            "evidence": {
                "rule_id": "1-5-cors-misconfig",
                "url": "http://localhost:8081",
                "acao": "https://cors-probe.invalid",
                "acac": "true",
            },
        },
    ]

    selected = selector.select_representatives(findings, limit=8)

    assert len(selected) == 3
    rule_ids = {row["evidence"]["rule_id"] for row in selected}
    assert rule_ids == {"1-5-reflected-xss-probe", "1-5-open-redirect", "1-5-cors-misconfig"}
    # highest severity / confirmed findings sort first
    assert selected[0]["evidence"]["rule_id"] in {"1-5-open-redirect", "1-5-cors-misconfig"}


def test_select_representatives_keeps_higher_ranked_duplicate():
    selector = _load_selector()
    findings = [
        {
            "severity": "low",
            "evidence": {
                "rule_id": "1-5-open-redirect",
                "test_url": "http://localhost:8080/redirect?next=https://evil.example",
                "param_name": "next",
                "confirmed_redirect": False,
            },
        },
        {
            "severity": "high",
            "evidence": {
                "rule_id": "1-5-open-redirect",
                "test_url": "http://localhost:8080/redirect?next=https://evil.example",
                "param_name": "next",
                "confirmed_redirect": True,
            },
        },
    ]

    selected = selector.select_representatives(findings, limit=8)

    assert len(selected) == 1
    assert selected[0]["severity"] == "high"
    assert selected[0]["evidence"]["confirmed_redirect"] is True


def test_resolve_target_url_ignores_non_navigable_location():
    selector = _load_selector()
    evidence = {
        "location": "REFLECTED_XSS:<script>x</script>",
        "url": "http://localhost:8080/api/v1/members/me/profile?userId=1",
    }
    assert selector.resolve_target_url(evidence) == evidence["url"]


def test_stable_finding_id_is_deterministic():
    selector = _load_selector()
    finding = {
        "severity": "high",
        "evidence": {
            "rule_id": "1-5-cors-misconfig",
            "url": "http://localhost:8081",
        },
    }
    assert selector.stable_finding_id(finding) == selector.stable_finding_id(finding)
    assert selector.stable_finding_id(finding).startswith("1-5-")
