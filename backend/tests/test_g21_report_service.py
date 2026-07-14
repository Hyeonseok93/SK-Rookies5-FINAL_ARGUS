"""Tests for the 2-1 evidence report service (per-finding downloadable report)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from app.services import report_service

# 1x1 transparent PNG, real magic bytes.
_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _write_latest_yaml(data_dir: Path, findings: list[dict]) -> None:
    report_dir = data_dir / "report" / "2-1"
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "section_id": "2-1",
        "title": "악성코드파일 업로드",
        "chapter": 2,
        "status": "fail",
        "implemented": True,
        "findings": findings,
        "message": "",
        "checked_at": None,
    }
    (report_dir / "latest.yaml").write_text(yaml.safe_dump(payload, allow_unicode=True), encoding="utf-8")


_STATS_FINDING = {
    "severity": "info",
    "message": "2-1 scan statistics",
    "evidence": {"stats": {"targets": 1}},
}

_TRUE_POSITIVE_FINDING = {
    "severity": "high",
    "message": "disallowed extension accepted",
    "evidence": {
        "rule_id": "2-1-malicious-upload",
        "method": "POST",
        "path": "/api/v1/posts",
        "endpoint_id": "http://x:POST:/api/v1/posts",
        "extension": "php",
        "technique": "direct_extension",
        "reason": "disallowed_extension_accepted:direct_extension",
        "finding_type": "true_positive",
        "assessment": "정탐",
        "business_role": "user",
        "feature_label": "Posts / images",
        "url": "http://host.docker.internal:8080/api/v1/posts",
        "affected_urls": ["http://host.docker.internal:8080/api/v1/posts"],
    },
}

_FP_CANDIDATE_FINDING = {
    "severity": "info",
    "message": "baseline rejected",
    "evidence": {
        "rule_id": "2-1-malicious-upload",
        "method": "POST",
        "path": "/api/v1/seller/accommodations",
        "endpoint_id": "http://x:POST:/api/v1/seller/accommodations",
        "extension": "jpg",
        "technique": "baseline_valid",
        "reason": "baseline_upload_rejected",
        "finding_type": "false_positive_candidate",
        "assessment": "오탐 후보",
        "business_role": "seller",
        "feature_label": "Accommodations / thumbnail",
        "affected_urls": ["http://host.docker.internal:8080/api/v1/seller/accommodations"],
    },
}

_STACK_TRACE_FINDING = {
    "severity": "medium",
    "message": "upload response exposes stack trace",
    "evidence": {
        "rule_id": "2-1-malicious-upload",
        "method": "POST",
        "path": "/api/v1/posts",
        "endpoint_id": "http://x:POST:/api/v1/posts",
        "extension": "jpg",
        "technique": "baseline_valid",
        "reason": "path_exposure:stack_trace",
        "finding_type": "true_positive",
        "assessment": "정탐",
        "business_role": "user",
        "feature_label": "Posts / images",
        "affected_urls": [],
    },
}


def test_no_report_file_returns_empty_list(tmp_path: Path):
    assert report_service.build_report_items("2-1", data_dir=tmp_path) == []


def test_filters_to_true_positive_and_false_positive_candidate(tmp_path: Path):
    _write_latest_yaml(
        tmp_path,
        [_STATS_FINDING, _TRUE_POSITIVE_FINDING, _FP_CANDIDATE_FINDING],
    )

    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    assert len(items) == 2
    verdicts = {item["reason"]: item["verdict"] for item in items}
    assert verdicts["disallowed_extension_accepted:direct_extension"] == "확정 취약"
    assert verdicts["baseline_upload_rejected"] == "잠재적 취약 (추가 검증 필요)"


def test_stack_trace_path_exposure_finding_is_included(tmp_path: Path):
    _write_latest_yaml(tmp_path, [_STACK_TRACE_FINDING])

    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    assert len(items) == 1
    assert items[0]["reason"] == "path_exposure:stack_trace"
    assert "6-1" in items[0]["remediation"]["guideline_ref"]


def test_missing_screenshot_evidence_yields_empty_list(tmp_path: Path):
    _write_latest_yaml(tmp_path, [_TRUE_POSITIVE_FINDING])

    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    assert len(items) == 1
    assert items[0]["screenshots"] == []


def _load_real_selector():
    import importlib.util
    import sys

    selector_path = Path(report_service.__file__).resolve().parents[2] / "screenshot" / "modules" / "2-1" / "selector.py"
    spec = importlib.util.spec_from_file_location("test_g21_report_selector", selector_path)
    assert spec and spec.loader
    selector = importlib.util.module_from_spec(spec)
    sys.modules["test_g21_report_selector"] = selector
    spec.loader.exec_module(selector)
    return selector


def test_screenshot_is_embedded_and_recompressed_to_jpeg(tmp_path: Path):
    _write_latest_yaml(tmp_path, [_TRUE_POSITIVE_FINDING])
    selector = _load_real_selector()

    finding_id = selector.stable_finding_id(_TRUE_POSITIVE_FINDING)
    evidence_dir = tmp_path / "report" / "2-1" / "evidence" / finding_id
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "05_attack_evidence.png").write_bytes(_PNG_BYTES)
    (evidence_dir / "manifest.json").write_text(
        json.dumps({"artifacts": [{"kind": "attack_evidence", "path": "/app/whatever/05_attack_evidence.png"}]}),
        encoding="utf-8",
    )

    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    assert len(items) == 1
    shots = items[0]["screenshots"]
    assert len(shots) == 1
    assert shots[0]["kind"] == "attack_evidence"
    # Re-encoded as JPEG to keep the report small — no longer the original PNG bytes.
    assert shots[0]["data_uri"].startswith("data:image/jpeg;base64,")
    decoded = base64.b64decode(shots[0]["data_uri"].split(",", 1)[1])
    assert decoded != _PNG_BYTES
    from PIL import Image
    from io import BytesIO

    with Image.open(BytesIO(decoded)) as img:
        assert img.format == "JPEG"
        assert img.size == (1, 1)


def test_findings_with_same_vulnerability_are_merged_by_finding_id(tmp_path: Path):
    """Two raw findings differing only by auth_mode collapse to one report
    item — otherwise the same screenshot set gets embedded once per variant
    and bloats the report."""
    variant_a = json.loads(json.dumps(_TRUE_POSITIVE_FINDING))
    variant_a["evidence"]["auth_mode"] = "authenticated:a@travel.com:login"
    variant_a["evidence"]["affected_urls"] = ["http://x/api/v1/posts?memberId=1"]

    variant_b = json.loads(json.dumps(_TRUE_POSITIVE_FINDING))
    variant_b["evidence"]["auth_mode"] = "authenticated:b@travel.com:login"
    variant_b["evidence"]["affected_urls"] = ["http://x/api/v1/posts?memberId=2"]

    _write_latest_yaml(tmp_path, [variant_a, variant_b])

    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    assert len(items) == 1
    assert set(items[0]["auth_modes"]) == {
        "authenticated:a@travel.com:login",
        "authenticated:b@travel.com:login",
    }
    assert set(items[0]["affected_urls"]) == {
        "http://x/api/v1/posts?memberId=1",
        "http://x/api/v1/posts?memberId=2",
    }


def test_guideline_lookup_extension_bypass_matches_technique_detail():
    guideline = report_service._load_guideline("2-1")
    result = report_service._guideline_lookup(guideline, "disallowed_extension_accepted:double_extension")

    assert "2-1" in result["guideline_ref"]
    assert "double_extension" not in result["guideline_ref"]  # sanity: ref text, not the key itself
    assert "이중 확장자" in result["note"]


def test_guideline_lookup_path_exposure_stack_trace_cites_6_1():
    guideline = report_service._load_guideline("2-1")
    result = report_service._guideline_lookup(guideline, "path_exposure:stack_trace")

    assert "6-1" in result["guideline_ref"]
    assert "remediation" in result


def test_guideline_lookup_baseline_rejected_has_no_guideline_ref():
    guideline = report_service._load_guideline("2-1")
    result = report_service._guideline_lookup(guideline, "baseline_upload_rejected")

    assert result.get("guideline_ref") is None
    assert "note" in result


def test_render_report_html_shows_missing_screenshot_placeholder(tmp_path: Path):
    _write_latest_yaml(tmp_path, [_TRUE_POSITIVE_FINDING])
    items = report_service.build_report_items("2-1", data_dir=tmp_path)

    html_doc = report_service.render_report_html("2-1", "악성코드파일 업로드", items)

    assert "<html" in html_doc
    assert "확정 취약" in html_doc
    assert "스크린샷 미보유" in html_doc


def test_render_report_html_empty_state_when_no_items():
    html_doc = report_service.render_report_html("2-1", "악성코드파일 업로드", [])
    assert "finding이 없습니다" in html_doc
