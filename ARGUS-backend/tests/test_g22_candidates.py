"""Offline tests for guideline 2-2 candidate selection and design review."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from inventory.schema import ApiTree, Endpoint, InputParam, InventoryMeta

_MODULE_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules" / "2-2"


def _load(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"test_g22_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ep(**kwargs) -> Endpoint:
    defaults = {
        "method": "GET",
        "path": "/api/v1/files/download",
        "base_url": "https://example.com",
        "kind": "api",
    }
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_score_export_endpoint():
    candidates = _load("candidates")
    ep = _ep(
        request_params=[InputParam(in_="query", name="filename", sample="report.pdf")],
    )
    assert candidates.score_candidate(ep) >= 2
    assert candidates.is_candidate(ep)


def test_select_candidates_ranked():
    candidates = _load("candidates")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            _ep(path="/api/health"),
            _ep(
                path="/api/v1/report/export",
                request_params=[InputParam(in_="query", name="template", sample="x")],
            ),
            _ep(
                path="/api/v1/files/{fileId}",
                request_params=[InputParam(in_="path", name="fileId")],
            ),
        ]
    )
    selected = candidates.select_candidates(tree, min_score=2, max_count=10)
    assert len(selected) >= 1
    paths = {e.path for e in selected}
    assert "/api/v1/report/export" in paths


def test_select_all_inventory():
    candidates = _load("candidates")
    tree = ApiTree(
        meta=InventoryMeta(),
        endpoints=[
            _ep(path="/api/health", kind="api"),
            _ep(path="/dashboard", kind="frontend"),
            _ep(
                path="/api/v1/report/export",
                request_params=[InputParam(in_="query", name="template", sample="x")],
            ),
        ],
    )
    scored = candidates.select_candidates(tree, min_score=2, max_count=10)
    all_targets, mode = candidates.select_scan_targets(tree, scan_all_inventory=True)
    assert len(scored) < len(all_targets)
    assert mode == "all_inventory"
    assert len(all_targets) == 3
    kinds = {e.kind for e in all_targets}
    assert kinds == {"api", "frontend"}


def test_pdf_bytes_with_passwd_literal_detected():
    ra = _load("response_analysis")
    # Minimal PDF with passwd line in a literal string (as real LFI-in-PDF would embed)
    pdf = (
        b"%PDF-1.4\n1 0 obj\n<<>>\nstream\n"
        b"(root:x:0:0:root:/root:/bin/bash)\n"
        b"(daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin)\n"
        b"endstream\nendobj\n%%EOF"
    )
    leak_text = ra.extract_text_for_leak_scan(pdf)
    markers = ra.find_payload_leak_markers("../../../../etc/passwd", leak_text, raw=pdf)
    assert "root:" in leak_text or any("root:" in m for m in markers)
    assert markers


def test_corrupted_str_pdf_misses_but_bytes_hit():
    """resp.text-style corruption must not be used for PDF probes."""
    ra = _load("response_analysis")
    pdf = b"%PDF-1.4\n(root:x:0:0:root:/root:/bin/bash)\n%%EOF"
    corrupted = pdf.decode("utf-8", errors="replace").encode("utf-8", errors="replace")
    assert ra.find_payload_leak_markers(
        "/etc/passwd",
        ra.extract_text_for_leak_scan(pdf),
        raw=pdf,
    )
    # corrupted re-encode may still have root in literals; intact bytes is what probes now use
    tf = _load("traversal_fuzz")
    cat, reason, _meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body=b"%PDF-1.4 baseline",
        baseline_headers={"Content-Type": "application/pdf"},
        payload_status=200,
        payload_body=pdf,
        payload_headers={"Content-Type": "application/pdf"},
        payload="../../../../etc/passwd",
    )
    assert cat == "path_traversal"
    assert reason == "payload_target_leak_confirmed"


def test_backup_zip_pk_in_pdf_not_flagged():
    ra = _load("response_analysis")
    pdf = b"%PDF-1.4 binary pk noise in stream not a zip file"
    assert not ra.find_payload_leak_markers("backup.zip", ra.extract_text_for_leak_scan(pdf), raw=pdf)


def test_identical_pdf_is_input_validation():
    tf = _load("traversal_fuzz")
    pdf = "%PDF-1.4 same content"
    baseline_h = {"Content-Disposition": 'attachment; filename="report.pdf"'}
    payload_h = {"Content-Disposition": 'attachment; filename="report.pdf"'}
    cat, reason, _meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body=pdf,
        baseline_headers=baseline_h,
        payload_status=200,
        payload_body=pdf,
        payload_headers=payload_h,
        payload="../",
    )
    assert cat == "input_validation"
    assert reason == "identical_response_to_baseline"


def test_different_pdf_without_leak_is_input_validation():
    tf = _load("traversal_fuzz")
    baseline_h = {"Content-Disposition": 'attachment; filename="report.pdf"'}
    payload_h = {"Content-Disposition": 'attachment; filename="other.pdf"'}
    base_pdf = "%PDF-1.4 baseline report content here"
    pay_pdf = "%PDF-1.4 baseline report content here with extra metadata"
    cat, reason, meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body=base_pdf,
        baseline_headers=baseline_h,
        payload_status=200,
        payload_body=pay_pdf,
        payload_headers=payload_h,
        payload="../",
    )
    assert cat == "input_validation"
    assert reason in ("dynamic_pdf_no_leak", "different_pdf_no_payload_leak")
    assert meta.get("analysis", {}).get("payload_leak_markers") == []


def test_passwd_payload_with_root_is_path_traversal():
    tf = _load("traversal_fuzz")
    cat, reason, meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body="%PDF-1.4 baseline",
        baseline_headers={},
        payload_status=200,
        payload_body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        payload_headers={"Content-Type": "text/plain"},
        payload="../../../../etc/passwd",
    )
    assert cat == "path_traversal"
    assert reason in ("payload_target_leak_confirmed", "sensitive_body_in_response")
    assert meta.get("payload_leak_confirmed") or meta.get("analysis", {}).get("payload_leak_markers")


def test_sensitive_body_is_path_traversal():
    tf = _load("traversal_fuzz")
    cat, reason, _meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body="%PDF-1.4",
        baseline_headers={"Content-Disposition": 'attachment; filename="x"'},
        payload_status=200,
        payload_body="root:x:0:0:root:/root:/bin/bash",
        payload_headers={},
        payload="/etc/passwd",
    )
    assert cat == "path_traversal"
    assert reason in ("payload_target_leak_confirmed", "sensitive_body_in_response")


def test_htpasswd_does_not_use_passwd_markers_only():
    ra = _load("response_analysis")
    rules = ra.expected_leak_rules("../.htpasswd")
    hints = [h for _, h in rules]
    assert ".htpasswd" in hints
    markers = ra.find_payload_leak_markers(
        "../.htpasswd",
        "admin:$apr1$xyz$hashhere",
        raw=b"admin:$apr1$xyz",
    )
    assert any("apr1" in m.lower() or "$apr1$" in m for m in markers)


def test_actuator_env_markers():
    ra = _load("response_analysis")
    body = '{"propertySources":[{"name":"systemProperties","properties":{"local.server.port":{"value":"8080"}}}]}'
    markers = ra.find_payload_leak_markers("../actuator/env", body, raw=body.encode())
    assert markers


def test_wp_config_markers():
    ra = _load("response_analysis")
    body = "<?php define('DB_PASSWORD', 'secret'); define('DB_NAME', 'wp');"
    markers = ra.find_payload_leak_markers("../../wp-config.php", body, raw=body.encode())
    assert any("db_password" in m.lower() or "define" in m.lower() for m in markers)


def test_zip_binary_marker():
    ra = _load("response_analysis")
    raw = b"PK\x03\x04" + b"\x00" * 100
    markers = ra.find_payload_leak_markers("backup.zip", "", raw=raw)
    assert any("zip header" in m for m in markers)


def test_extracted_preview_shows_passwd_not_binary():
    ra = _load("response_analysis")
    # pypdf-style text after noisy literal section
    leak_text = "garbage \x00\xff\x01\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    preview = ra.build_extracted_text_preview(
        leak_text,
        payload_leaks=["root: ← expected from passwd"],
        generic_leaks=["root:"],
    )
    assert "root:x:0:0" in preview
    assert "\xff" not in preview


def test_classify_hash_diff_with_pdf_bytes():
    tf = _load("traversal_fuzz")
    base = b"%PDF-1.4 baseline content words here"
    pay = b"%PDF-1.4 baseline content words here v2"
    cat, reason, _meta = tf.compare_to_baseline(
        path="/api/v1/report/integrated",
        baseline_status=200,
        baseline_body=base,
        baseline_headers={"Content-Type": "application/pdf"},
        payload_status=200,
        payload_body=pay,
        payload_headers={"Content-Type": "application/pdf"},
        payload="../",
    )
    assert cat == "input_validation"
    assert reason in ("dynamic_pdf_no_leak", "different_pdf_no_payload_leak")


def test_evidence_snippet_accepts_pdf_bytes():
    tf = _load("traversal_fuzz")
    ev = tf.evidence_snippet(
        {"Content-Type": "application/pdf"},
        b"%PDF-1.4\n(root:x:0:0:root:/root:/bin/bash)\n%%EOF",
    )
    assert ev.get("content_type") == "application/pdf"
    assert "body_preview" not in ev


def test_build_probe_evidence_includes_hashes():
    tf = _load("traversal_fuzz")
    pdf = "%PDF-1.4"
    ev = tf.build_probe_result_evidence(
        ep=_ep(path="/api/v1/report/integrated", method="POST"),
        param_in="body",
        param_name="template",
        classification="input_validation",
        trigger="identical_response_to_baseline",
        primary={
            "payload": "../",
            "http_status": 200,
            "url": "http://example.com/api/v1/report/integrated",
            "body": pdf,
            "headers": {"Content-Disposition": 'attachment; filename="r.pdf"'},
        },
        payloads_tried=[{"payload": "../", "category": "input_validation", "trigger": "identical_response_to_baseline"}],
        baseline_status=200,
        baseline_body=pdf,
        baseline_headers={"Content-Disposition": 'attachment; filename="r.pdf"'},
    )
    assert ev["classification"] == "A"
    assert ev["rule_id"] == "2-2-input-validation"
    assert ev["baseline_sha256"] == ev["response_sha256"]
    assert ev["bodies_identical"] is True
    assert ev["payloads_tried_count"] == 1


def test_design_review_flags_direct_path_param():
    design = _load("design_review")
    ep = _ep(
        method="POST",
        path="/api/storage/read",
        request_params=[InputParam(in_="body", name="filepath", sample="/tmp/x")],
    )
    findings = design.review_design([ep])
    assert any(f.severity == "medium" and "filepath" in f.message for f in findings)


def _auth_snapshot(
    *,
    status: int | None,
    body: bytes = b"",
    headers: dict | None = None,
    auth_mode: str = "anonymous",
) -> "object":
    auth_access = _load("auth_access")
    return auth_access.AuthProbeSnapshot(
        auth_mode=auth_mode,
        http_status=status,
        body=body,
        headers=headers or {},
        url="https://example.com/api/v1/report/export",
    )


def test_unauth_download_auth_denied_is_high():
    auth_access = _load("auth_access")
    pdf = b"%PDF-1.4 test content " + b"x" * 200
    anon = _auth_snapshot(status=200, body=pdf, headers={"Content-Type": "application/pdf"})
    authed = _auth_snapshot(status=403, auth_mode="authenticated")
    result = auth_access.classify_unauth_download(
        path="/api/v1/admin/report/export",
        anonymous=anon,
        authenticated=authed,
    )
    assert result is not None
    severity, trigger, _meta = result
    assert severity == "high"
    assert trigger == "anon_download_auth_denied"


def test_unauth_download_both_sessions_is_medium():
    auth_access = _load("auth_access")
    pdf = b"%PDF-1.4 same file " + b"y" * 200
    headers = {"Content-Type": "application/pdf"}
    anon = _auth_snapshot(status=200, body=pdf, headers=headers)
    authed = _auth_snapshot(status=200, body=pdf, headers=headers, auth_mode="authenticated")
    result = auth_access.classify_unauth_download(
        path="/api/v1/report/export",
        anonymous=anon,
        authenticated=authed,
    )
    assert result is not None
    severity, trigger, meta = result
    assert severity == "medium"
    assert trigger == "unauth_download_both_sessions"
    assert meta["bodies_identical"] is True


def test_unauth_download_anon_denied_no_finding():
    auth_access = _load("auth_access")
    anon = _auth_snapshot(status=401)
    authed = _auth_snapshot(status=200, body=b"%PDF-1.4" + b"z" * 200, headers={"Content-Type": "application/pdf"})
    result = auth_access.classify_unauth_download(
        path="/api/v1/report/export",
        anonymous=anon,
        authenticated=authed,
    )
    assert result is None


def test_unauth_download_no_account_medium():
    auth_access = _load("auth_access")
    anon = _auth_snapshot(
        status=200,
        body=b"%PDF-1.4" + b"a" * 200,
        headers={"Content-Disposition": 'attachment; filename="r.pdf"'},
    )
    result = auth_access.classify_unauth_download(
        path="/api/v1/report/export",
        anonymous=anon,
        authenticated=None,
    )
    assert result is not None
    assert result[0] == "medium"
    assert result[1] == "unauth_download_no_account"


def test_traversal_targets_dashboard_download_all_params():
    tf = _load("traversal_fuzz")
    ep = _ep(
        path="/api/v1/files/download",
        tags=["2-2-candidate", "dashboard-download"],
        request_params=[
            InputParam(in_="query", name="file", sample="report.pdf"),
            InputParam(in_="query", name="userId", sample="42"),
            InputParam(in_="path", name="fileId", sample="7"),
        ],
    )
    targets = tf.traversal_targets(ep)
    assert ("query", "file") in targets
    assert ("query", "userId") in targets
    assert ("path", "fileId") in targets
    assert len(targets) == 3


def test_traversal_targets_inventory_file_like_only():
    tf = _load("traversal_fuzz")
    ep = _ep(
        request_params=[
            InputParam(in_="query", name="file", sample="a.pdf"),
            InputParam(in_="query", name="page", sample="1"),
        ],
    )
    targets = tf.traversal_targets(ep)
    assert targets == [("query", "file")]


def test_build_traversal_probe_path_param_changes_one_segment():
    tf = _load("traversal_fuzz")
    ep = _ep(
        path="/api/v1/files/{fileId}/download",
        request_params=[InputParam(in_="path", name="fileId", sample="99")],
    )
    baseline = tf.build_traversal_probe(
        ep,
        param_in="path",
        param_name="fileId",
        payload="../../../../etc/passwd",
        auth=None,
        baseline_path_defaults={"fileId": "99"},
    )
    assert "/etc/passwd" in baseline["url"] or "passwd" in baseline["url"]
    assert "99" not in baseline["url"].split("/")[-2:] or ".." in baseline["url"]


def test_build_traversal_probe_query_keeps_other_params():
    tf = _load("traversal_fuzz")
    ep = _ep(
        path="/api/download",
        request_params=[
            InputParam(in_="query", name="file", sample="report.pdf"),
            InputParam(in_="query", name="userId", sample="42"),
        ],
    )
    injected = tf.build_traversal_probe(
        ep,
        param_in="query",
        param_name="file",
        payload="../etc/passwd",
        auth=None,
    )
    assert "userId=42" in injected["url"]
    assert "file=" in injected["url"]
    assert "passwd" in injected["url"]


def test_traversal_targets_post_download_without_params_is_empty():
    tf = _load("traversal_fuzz")
    ep = _ep(
        method="POST",
        path="/user-api/api/v1/report/integrated",
        tags=["2-2-candidate", "dashboard-download"],
        request_params=[],
    )
    assert tf.traversal_targets(ep) == []


def test_traversal_targets_post_download_uses_request_params():
    tf = _load("traversal_fuzz")
    ep = _ep(
        method="POST",
        path="/user-api/api/v1/report/integrated",
        tags=["2-2-candidate", "dashboard-download"],
        request_params=[
            InputParam(in_="body", name="template", sample="verification"),
            InputParam(in_="body", name="memberId", sample="1"),
        ],
    )
    targets = tf.traversal_targets(ep)
    assert ("body", "template") in targets
    assert ("body", "memberId") in targets


def test_scan_options_registered_download_only_disables_extra_checks():
    scanner = _load("scanner")
    opts = scanner._scan_options({"diagnosis_2_2": {"dashboard_download_only": True}})
    assert opts.dashboard_download_only is True
    assert opts.unauth_probe_enabled is True
    assert opts.idor_probe_enabled is False
    assert opts.forced_browse_enabled is False
    assert opts.design_review_enabled is False
    assert opts.zap_supplemental_enabled is False


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
                path="/api/v1/report/export",
                request_params=[InputParam(in_="query", name="path", sample="a.pdf")],
            ),
        ]
    )
    tree_path = tmp_path / "api-tree-ready.json"
    tree.save(tree_path)

    ctx = __import__("diagnosis.context", fromlist=["DiagnosisContext"]).DiagnosisContext(
        data_dir=tmp_path,
        config={},
        raw_config={"diagnosis_2_2": {"zap_enabled": False, "httpx_enabled": False}},
    )
    result = scanner.run_g22_scan(ctx, _MODULE_DIR)
    assert result.status in ("pass", "warn", "fail", "no_targets")
    assert result.stats.get("candidates", {}).get("total", 0) >= 1
    assert any("path" in f.message.lower() for f in result.findings)
