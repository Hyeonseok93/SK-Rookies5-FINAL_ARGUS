from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load(name: str):
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-2" / f"{name}.py"
    module_dir = path.parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    mod_name = f"g22_{name}_test"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_unauth_overlay_labels_authenticated_vs_anonymous():
    models = _load("models")
    renderer = _load("renderer")
    case = models.EvidenceCase(
        finding_id="2-2-test",
        section_id="2-2",
        title="unauth download",
        rule_id="2-2-unauth-download",
        parameter="-",
        payload="-",
        trigger="unauth_download_both_sessions",
        baseline=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
            status_code=200,
            response_body="AUTH_OK",
        ),
        attack=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
            status_code=200,
            response_body="ANON_OK",
        ),
    )
    css, markup = renderer.render_evidence_overlay(case, "baseline")
    assert "Authenticated Request" in markup
    assert "AUTH_OK" in markup
    css2, markup2 = renderer.render_evidence_overlay(case, "attack")
    assert "Unauthenticated Request" in markup2
    assert "ANON_OK" in markup2
    assert "argus-evidence-bottom" in markup
    assert "#argus-evidence-root" in css
    assert "#argus-evidence-root" in css2


def test_resolve_unauth_ui_flow_from_replay_steps():
    ui_flow = _load("ui_flow")
    models = _load("models")
    case = models.EvidenceCase(
        finding_id="2-2-ui",
        section_id="2-2",
        title="unauth",
        rule_id="2-2-unauth-download",
        parameter="-",
        payload="-",
        trigger="unauth_download_both_sessions",
        baseline=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
        ),
        attack=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
        ),
        metadata={
            "main_url": "http://host.docker.internal:5173/",
            "main_display_url": "http://localhost:5173/",
            "source_evidence": {
                "replay": {
                    "steps": [
                        {
                            "action": "navigate",
                            "label": "메인 페이지",
                            "url": "http://localhost:5173/",
                        },
                        {
                            "action": "navigate",
                            "label": "마이페이지",
                            "url": "http://localhost:5173/mypage",
                        },
                        {
                            "action": "scroll",
                            "label": "정산서 발급 위젯",
                            "selector": "#reportTemplate",
                        },
                        {
                            "action": "click",
                            "label": "통합 정산서 PDF 다운로드 버튼",
                            "selector": "button:has-text('통합 정산서 PDF 다운로드')",
                        },
                    ]
                }
            },
        },
    )
    flow = ui_flow.resolve_unauth_ui_flow(case)
    assert flow["ui_route_source"] == "replay-steps"
    assert flow["feature_route"] == "/mypage"
    assert flow["feature_label"] == "마이페이지"
    assert flow["main_url"].endswith("/")
    assert "/mypage" in flow["feature_url"]
    assert len(flow["prep_steps"]) == 2
    assert flow["prep_steps"][0]["selector"] == "#reportTemplate"


def test_resolve_unauth_ui_flow_from_yaml_when_replay_missing():
    ui_flow = _load("ui_flow")
    models = _load("models")
    case = models.EvidenceCase(
        finding_id="2-2-ui",
        section_id="2-2",
        title="unauth",
        rule_id="2-2-unauth-download",
        parameter="-",
        payload="-",
        trigger="unauth_download_both_sessions",
        baseline=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
        ),
        attack=models.HttpExchange(
            method="POST",
            url="http://host.docker.internal:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
        ),
        metadata={
            "main_url": "http://host.docker.internal:5173/",
            "main_display_url": "http://localhost:5173/",
        },
    )
    flow = ui_flow.resolve_unauth_ui_flow(case)
    assert flow["ui_route_source"] == "ui-flows-yaml"
    assert flow["feature_route"] == "/mypage"
    assert "/mypage" in flow["feature_url"]


def test_probe_capture_kinds_use_authenticated_ui_flow():
    engine = _load("engine")
    assert [kind for kind, _ in engine.PROBE_CAPTURES] == [
        "main_site",
        "logged_in_main",
        "feature_page",
        "baseline_evidence",
        "attack_evidence",
        "ui_result",
    ]
    assert engine._page_url_for_kind(
        "logged_in_main",
        main_url="http://localhost:5173/",
        feature_url="http://localhost:5173/mypage",
    ) == "http://localhost:5173/"
    assert engine._page_url_for_kind(
        "baseline_evidence",
        main_url="http://localhost:5173/",
        feature_url="http://localhost:5173/mypage",
    ) == "http://localhost:5173/mypage"


def test_traversal_overlay_labels_baseline_vs_exploit():
    models = _load("models")
    renderer = _load("renderer")
    case = models.EvidenceCase(
        finding_id="2-2-pt",
        section_id="2-2",
        title="path traversal",
        rule_id="2-2-path-traversal",
        parameter="template",
        payload="../../etc/passwd",
        trigger="payload_target_leak_confirmed",
        baseline=models.HttpExchange(
            method="POST",
            url="http://localhost:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
            response_body="BASELINE_OK",
        ),
        attack=models.HttpExchange(
            method="POST",
            url="http://localhost:8080/api/v1/report/integrated",
            display_url="http://localhost:8080/api/v1/report/integrated",
            response_body="LEAKED",
        ),
    )
    css, markup = renderer.render_evidence_overlay(case, "baseline")
    assert "Baseline Request" in markup
    assert "BASELINE_OK" in markup
    css2, markup2 = renderer.render_evidence_overlay(case, "attack")
    assert "Exploit Request" in markup2
    assert "LEAKED" in markup2
    assert "#argus-evidence-root" in css


def test_unauth_capture_kinds_include_feature_page_after_main():
    engine = _load("engine")
    assert [kind for kind, _ in engine.UNAUTH_CAPTURES] == [
        "main_site",
        "feature_page",
        "auth_evidence",
        "anon_evidence",
        "ui_result",
    ]
    assert engine.UNAUTH_FILE_COMPARE_CAPTURE == ("file_compare", "07_file_compare.png")
    assert engine._page_url_for_kind(
        "main_site",
        main_url="http://localhost:5173/",
        feature_url="http://localhost:5173/report",
    ) == "http://localhost:5173/"
    assert engine._page_url_for_kind(
        "feature_page",
        main_url="http://localhost:5173/",
        feature_url="http://localhost:5173/report",
    ) == "http://localhost:5173/report"
    assert engine._page_url_for_kind(
        "auth_evidence",
        main_url="http://localhost:5173/",
        feature_url="http://localhost:5173/report",
    ) == "http://localhost:5173/report"


def test_response_panel_does_not_dump_pdf_mojibake():
    models = _load("models")
    renderer = _load("renderer")
    pdf = b"%PDF-1.4\n(Hello Settlement Report)\nendstream\nendobj\n"
    exchange = models.HttpExchange(
        method="POST",
        url="http://localhost:8080/api/v1/report/integrated",
        display_url="http://localhost:8080/api/v1/report/integrated",
        status_code=200,
        response_headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="onde_settlement_report.pdf"',
        },
        # Simulate the old bug: UTF-8-decoded binary sitting in response_body.
        response_body=pdf.decode("utf-8", errors="replace"),
        response_body_raw=pdf,
    )
    rendered = renderer._response(exchange)
    assert "endobj" not in rendered or "[download body]" in rendered
    assert "\ufffd" not in rendered
    assert "onde_settlement_report.pdf" in rendered
    assert "Hello Settlement Report" in rendered


def test_file_compare_detects_pdf_and_builds_preview():
    models = _load("models")
    compare = _load("file_compare")
    renderer = _load("renderer")
    pdf = b"%PDF-1.4\n(Hello Settlement Report)\ntrailer"
    auth = models.HttpExchange(
        method="POST",
        url="http://localhost:8080/api/v1/report/integrated",
        display_url="http://localhost:8080/api/v1/report/integrated",
        status_code=200,
        response_headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'form-data; name="attachment"; filename="onde_settlement_report.pdf"',
        },
        response_body_raw=pdf,
    )
    anon = models.HttpExchange(
        method="POST",
        url="http://localhost:8080/api/v1/report/integrated",
        display_url="http://localhost:8080/api/v1/report/integrated",
        status_code=200,
        response_headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'form-data; name="attachment"; filename="onde_settlement_report.pdf"',
        },
        response_body_raw=pdf + b"\n(extra)",
    )
    assert compare.looks_like_download(auth) is True
    detail = compare.build_file_compare(auth, anon)
    assert detail["identical"] is False
    assert detail["auth"]["filename"] == "onde_settlement_report.pdf"
    assert "Hello Settlement Report" in detail["auth"]["preview"]

    baseline = models.HttpExchange(
        method="POST",
        url="http://localhost:8080/api/v1/report/integrated",
        display_url="http://localhost:8080/api/v1/report/integrated",
        status_code=200,
        response_headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="onde_settlement_report.pdf"',
        },
        response_body_raw=pdf,
    )
    exploit = models.HttpExchange(
        method="POST",
        url="http://localhost:8080/api/v1/report/integrated",
        display_url="http://localhost:8080/api/v1/report/integrated",
        status_code=200,
        response_headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="onde_settlement_report.pdf"',
        },
        response_body_raw=b"%PDF-1.4\n(LEAKED_LOG_LINE in exploit PDF)\ntrailer",
    )
    probe_detail = compare.build_file_compare(
        baseline, exploit, mode="baseline_vs_attack"
    )
    assert probe_detail["mode"] == "baseline_vs_attack"
    assert probe_detail["identical"] is False
    assert "LEAKED_LOG_LINE" in probe_detail["attack"]["preview"]

    case = models.EvidenceCase(
        finding_id="2-2-file",
        section_id="2-2",
        title="unauth download",
        rule_id="2-2-unauth-download",
        parameter="-",
        payload="-",
        trigger="unauth_download_both_sessions",
        baseline=auth,
        attack=anon,
        metadata={"file_compare_detail": detail},
    )
    css, markup = renderer.render_file_compare_overlay(case)
    assert "File Content Compare" in markup
    assert "Authenticated File" in markup
    assert "Unauthenticated File" in markup
    assert "onde_settlement_report.pdf" in markup
    assert "파일 내용 다름" not in markup
    assert "DIFFERENT" not in markup
    assert "IDENTICAL" not in markup
    assert "#argus-evidence-root" in css

    probe_case = models.EvidenceCase(
        finding_id="2-2-pt-file",
        section_id="2-2",
        title="path traversal",
        rule_id="2-2-path-traversal",
        parameter="logoUrl",
        payload="/var/log/apache2/access.log",
        trigger="payload_target_leak_confirmed",
        baseline=baseline,
        attack=exploit,
        metadata={"file_compare_detail": probe_detail},
    )
    _, probe_markup = renderer.render_file_compare_overlay(probe_case)
    assert "Baseline vs Exploit" in probe_markup
    assert "Baseline File (정상)" in probe_markup
    assert "Exploit File (공격)" in probe_markup
    assert "LEAKED_LOG_LINE" in probe_markup


def test_probe_capture_appends_file_compare_when_detail_present():
    engine = _load("engine")
    assert engine.PROBE_FILE_COMPARE_CAPTURE == ("file_compare", "07_file_compare.png")
