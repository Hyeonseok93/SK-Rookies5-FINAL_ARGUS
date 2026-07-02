"""Offline tests for guideline 1-3 param/hidden-field manipulation scan."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from diagnosis.probe_transport import ProbeResponse
from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "1-3"
_ASSETS_DIR = _MODULE_DIR / "assets"


def _load(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"test_g13_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ep(**kwargs) -> Endpoint:
    defaults = {
        "method": "POST",
        "path": "/api/v1/insurances/calculate",
        "base_url": "https://example.com",
        "kind": "api",
    }
    defaults.update(kwargs)
    return Endpoint(**defaults)


def _resp(*, status: int | None, body: bytes = b"", headers: dict | None = None, error: str | None = None) -> ProbeResponse:
    return ProbeResponse(status=status, body=body, headers=headers or {}, error=error)


# ── param_classify ──────────────────────────────────────────────────

def test_classify_price():
    pc = _load("param_classify")
    result = pc.classify_param_name("totalPremium", assets_dir=_ASSETS_DIR)
    assert result is not None
    assert result[0] == "PRICE"


def test_classify_privilege_camelcase():
    pc = _load("param_classify")
    result = pc.classify_param_name("isAdmin", assets_dir=_ASSETS_DIR)
    assert result is not None
    assert result[0] == "PRIVILEGE"


def test_classify_idor_camelcase():
    pc = _load("param_classify")
    result = pc.classify_param_name("memberId", assets_dir=_ASSETS_DIR)
    assert result is not None
    assert result[0] == "IDOR"


def test_classify_status():
    pc = _load("param_classify")
    result = pc.classify_param_name("orderStatus", assets_dir=_ASSETS_DIR)
    assert result is not None
    assert result[0] == "STATUS"


def test_classify_enum():
    pc = _load("param_classify")
    result = pc.classify_param_name("coverageLevel", assets_dir=_ASSETS_DIR)
    assert result is not None
    assert result[0] == "ENUM"


def test_classify_safe():
    pc = _load("param_classify")
    assert pc.classify_param_name("keyword", assets_dir=_ASSETS_DIR) is None
    assert pc.classify_param_name("page", assets_dir=_ASSETS_DIR) is None


# ── mutations ────────────────────────────────────────────────────────

def test_mutations_idor_dynamic():
    m = _load("mutations")
    muts = m.mutations_for("IDOR", "5", assets_dir=_ASSETS_DIR)
    values = {v for v, _ in muts}
    assert "0" in values
    assert "6" in values  # base + 1


def test_mutations_idor_non_numeric_skipped():
    m = _load("mutations")
    assert m.mutations_for("IDOR", "not-a-number", assets_dir=_ASSETS_DIR) == []


def test_mutations_price_static():
    m = _load("mutations")
    muts = m.mutations_for("PRICE", "10000", assets_dir=_ASSETS_DIR)
    values = {v for v, _ in muts}
    assert "0" in values
    assert "-1" in values


def test_mutations_unknown_category_empty():
    m = _load("mutations")
    assert m.mutations_for("SAFE", "1", assets_dir=_ASSETS_DIR) == []


# ── candidates ───────────────────────────────────────────────────────

def test_score_candidate_with_sensitive_body_param():
    candidates = _load("candidates")
    ep = _ep(
        request_params=[InputParam(in_="body", name="totalPremium", sample="10000")],
    )
    assert candidates.score_candidate(ep, assets_dir=_ASSETS_DIR) >= 2
    assert candidates.is_candidate(ep, assets_dir=_ASSETS_DIR)


def test_score_candidate_no_sensitive_param():
    candidates = _load("candidates")
    ep = _ep(method="GET", path="/api/health", request_params=[])
    assert candidates.score_candidate(ep, assets_dir=_ASSETS_DIR) == 0
    assert not candidates.is_candidate(ep, assets_dir=_ASSETS_DIR)


def test_select_scan_targets_ranked():
    candidates = _load("candidates")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            _ep(method="GET", path="/api/health", request_params=[]),
            _ep(
                path="/api/v1/report/integrated",
                request_params=[InputParam(in_="body", name="memberId", sample="1")],
            ),
        ],
    )
    selected, mode = candidates.select_scan_targets(tree, assets_dir=_ASSETS_DIR, min_score=2, max_count=10)
    assert mode == "scored_api"
    assert len(selected) == 1
    assert selected[0].path == "/api/v1/report/integrated"


# ── compare ──────────────────────────────────────────────────────────

def _detect(**kwargs):
    compare = _load("compare")
    base = {
        "ep": _ep(),
        "param_in": "body",
        "param_name": "memberId",
        "category": "IDOR",
        "payload_value": "2",
        "payload_description": "test",
    }
    base.update(kwargs)
    return compare.detect_anomaly(**base)


def test_privilege_bypass_detected():
    finding = _detect(
        baseline=_resp(status=403, body=b"forbidden"),
        test=_resp(status=200, body=b'{"ok": true}'),
    )
    assert finding is not None
    assert finding.severity == "high"
    assert finding.evidence["anomaly_type"] == "PRIVILEGE_BYPASS"


def test_data_exposure_detected():
    finding = _detect(
        baseline=_resp(status=200, body=b'{"name": "a"}'),
        test=_resp(status=200, body=b'{"name": "a", "ssn": "999-99-9999"}'),
    )
    assert finding is not None
    assert finding.severity == "high"
    assert finding.evidence["anomaly_type"] == "DATA_EXPOSURE"


def test_potential_idor_detected():
    finding = _detect(
        baseline=_resp(status=200, body=b"x" * 10),
        test=_resp(status=200, body=b"y" * 600),
    )
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.evidence["anomaly_type"] == "POTENTIAL_IDOR"


def test_error_suppressed_detected():
    # Same JSON key shape in both responses (no new key) so the DATA_EXPOSURE check —
    # which runs first — doesn't shadow this: only the error keyword disappears.
    finding = _detect(
        baseline=_resp(status=200, body=b'{"result": "error: invalid amount"}'),
        test=_resp(status=200, body=b'{"result": "ok"}'),
    )
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.evidence["anomaly_type"] == "ERROR_SUPPRESSED"


def test_no_anomaly_when_responses_match():
    finding = _detect(
        baseline=_resp(status=200, body=b'{"result": "ok"}'),
        test=_resp(status=200, body=b'{"result": "ok"}'),
    )
    assert finding is None


def test_no_anomaly_when_request_failed():
    finding = _detect(
        baseline=_resp(status=200, body=b'{"result": "ok"}'),
        test=_resp(status=None, body=b"", error="timeout"),
    )
    assert finding is None


# ── design_review ────────────────────────────────────────────────────

def test_design_review_flags_optional_sensitive_body_param():
    design = _load("design_review")
    candidates = _load("candidates")
    ep = _ep(
        request_params=[InputParam(in_="body", name="memberId", sample="1", required=False)],
    )
    findings = design.review_design(
        [ep],
        sensitive_params_fn=lambda e: candidates.sensitive_params(e, assets_dir=_ASSETS_DIR),
    )
    assert any(f.severity == "info" and "memberId" in f.message for f in findings)


def test_design_review_skips_required_param():
    design = _load("design_review")
    candidates = _load("candidates")
    ep = _ep(
        request_params=[InputParam(in_="body", name="memberId", sample="1", required=True)],
    )
    findings = design.review_design(
        [ep],
        sensitive_params_fn=lambda e: candidates.sensitive_params(e, assets_dir=_ASSETS_DIR),
    )
    assert findings == []


# ── scanner (offline, design-review only) ───────────────────────────

def test_scanner_offline_design_only(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "diagnosis.replay.normalize.load_dashboard_base_urls",
        lambda explicit=None: ["https://example.com"],
    )
    scanner = _load("scanner")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            _ep(
                path="/api/v1/report/integrated",
                request_params=[InputParam(in_="body", name="memberId", sample="1", required=False)],
            ),
        ],
    )
    tree_path = tmp_path / "api-tree-ready.json"
    tree.save(tree_path)

    from diagnosis.context import DiagnosisContext

    ctx = DiagnosisContext(
        data_dir=tmp_path,
        config={},
        raw_config={"diagnosis_1_3": {"httpx_enabled": False}},
    )
    result = scanner.run_g13_scan(ctx, _MODULE_DIR)
    assert result.status in ("pass", "warn", "fail", "no_targets")
    assert result.stats.get("candidates", {}).get("total", 0) >= 1
    assert any("memberId" in f.message for f in result.findings)
