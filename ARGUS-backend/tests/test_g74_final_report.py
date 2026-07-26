from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def _load_generate_module():
    module_dir = Path(__file__).resolve().parents[1] / "report" / "modules" / "7-4"
    for name in ("builder", "guidelines", "models", "pdf_exporter", "renderer"):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(module_dir))
    spec = importlib.util.spec_from_file_location("g74_report_generate", module_dir / "generate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case_id(prefix: str, value: str) -> str:
    return f"7-4-{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"


def test_g74_report_builds_web_and_sca_pages_with_deps_notice(tmp_path: Path):
    generate = _load_generate_module()
    report_path = tmp_path / "latest.yaml"
    evidence_dir = tmp_path / "evidence"
    output = tmp_path / "final"
    web_id = _case_id("web", "https://example.test|missing_csp")
    sca_id = _case_id("sca", "org.example:sample:1.0.0")
    report_path.write_text(
        """section_id: 7-4
title: 취약한 보안설정
status: fail
checked_at: '2026-07-14T10:00:00+09:00'
findings:
- severity: info
  message: 7-4 scan statistics
  evidence:
    stats: {targets: 1}
- severity: medium
  message: Missing CSP
  evidence:
    source: httpx
    check_type: missing_csp
    reason: Content-Security-Policy not set
    base_url: https://example.test
    url: https://example.test/login
    header: content-security-policy
- severity: high
  message: Vulnerable dependency
  evidence:
    source: sca
    check_type: vulnerable_dependency
    component: org.example:sample
    version: 1.0.0
    cve_ids: [GHSA-test-0000-0000]
""",
        encoding="utf-8",
    )
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d49444154789c6360000000020001e221bc330000000049454e44ae426082"
    )
    results = []
    for case_id, case_type, kind in (
        (web_id, "web", "combined"),
        (sca_id, "sca", "dependency"),
    ):
        case_dir = evidence_dir / case_id
        case_dir.mkdir(parents=True)
        image = case_dir / "evidence.png"
        image.write_bytes(png)
        row = {
            "case_id": case_id,
            "type": case_type,
            "ok": True,
            "artifacts": [{"kind": kind, "path": str(image)}],
        }
        if case_type == "sca":
            row["representative"] = {
                "advisory_id": "GHSA-test-0000-0000",
                "severity": "high",
                "cvss_version": "3.1",
                "cvss_score": 9.8,
                "recommended_version": "1.0.2",
            }
        results.append(row)
    (evidence_dir / "capture-summary.json").write_text(
        json.dumps({"section_id": "7-4", "results": results}, ensure_ascii=False),
        encoding="utf-8",
    )

    result = generate.generate_report(report_path, evidence_dir, output, include_pdf=False)

    assert result["ok"] is True
    assert result["findings"] == 2
    html = (output / "report.html").read_text(encoding="utf-8")
    assert "deps 파일을 반드시 첨부" in html
    assert "API List, URL List, Swagger 및 Base URL만으로는" in html
    assert "https://example.test/login" in html
    assert "Content-Security-Policy 미설정" in html
    assert "<h2>Missing CSP</h2>" not in html
    assert "오픈소스 의존성 취약점 - org.example:sample 1.0.0" in html
    assert "grid-template-columns:1fr" in html
    assert "org.example:sample:1.0.0" in html
    assert "https://github.com/advisories/GHSA-test-0000-0000" in html
    assert "1.0.2 이상 버전" in html
    assert "SK Shieldus" not in html
    assert "SK 가이드라인" not in html
    first_method = html.index("탐지 기법 및 테스트 방법")
    first_image = html.index("data:image/png;base64", first_method)
    first_assessment = html.index("진단 결과 및 취약 판정 근거", first_image)
    first_remediation = html.index("대응방안", first_assessment)
    assert first_method < first_image < first_assessment < first_remediation

    document = generate.build_report(report_path, evidence_dir)
    document.findings = document.findings * 12
    paginated_html = generate.render_html(document)
    assert paginated_html.count('class="page summary-page') == 2
    assert paginated_html.count("<thead>") == 2
    assert "7-4 진단 결과 요약 - 계속" in paginated_html
    assert "3 / 51" in paginated_html
    assert "4 / 51" in paginated_html
    assert (output / "report-data.json").is_file()
    assert (output / "report-manifest.json").is_file()


def test_g74_generator_is_discovered_by_report_service():
    from app.services import report_generation_service

    assert report_generation_service.supports("7-4") is True
