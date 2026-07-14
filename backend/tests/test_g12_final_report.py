from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_generate_module():
    module_dir = Path(__file__).resolve().parents[1] / "report" / "modules" / "1-2"
    for name in ("builder", "guidelines", "models", "pdf_exporter", "renderer"):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(module_dir))
    spec = importlib.util.spec_from_file_location("g12_report_generate", module_dir / "generate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_g12_report_keeps_required_order_and_url(tmp_path: Path):
    generate = _load_generate_module()
    report_path = tmp_path / "latest.yaml"
    evidence_dir = tmp_path / "evidence"
    finding_dir = evidence_dir / "1-2-test"
    finding_dir.mkdir(parents=True)
    report_path.write_text(
        """section_id: 1-2
title: 삽입 공격 가능성
status: vulnerable
checked_at: '2026-07-14T10:00:00+09:00'
findings:
- severity: high
  message: SQL Injection 취약점
  evidence:
    finding_id: 1-2-test
    rule_id: G12_INJECTION
    method: GET
    url: http://example.test/api/members?id=1
    parameter: id
    custom_payload: "1' OR '1'='1"
    classification: CONFIRMED_BOOLEAN
    verification_status: VERIFIED
    confidence: HIGH
    injection_type: SQL
""",
        encoding="utf-8",
    )
    # A tiny valid PNG is sufficient because the report embeds, rather than decodes, it.
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d49444154789c6360000000020001e221bc330000000049454e44ae426082"
    )
    (finding_dir / "baseline.png").write_bytes(png)
    (finding_dir / "attack.png").write_bytes(png)
    (finding_dir / "manifest.json").write_text(
        json.dumps(
            {
                "finding_id": "1-2-test",
                "parameter": "id",
                "verification_type": "CONFIRMED_BOOLEAN",
                "confidence": "HIGH",
                "baseline": {
                    "method": "GET",
                    "url": "http://example.test/api/members?id=1",
                    "status_code": 200,
                    "response_body": "[]",
                    "elapsed_ms": 10,
                },
                "attack": {
                    "method": "GET",
                    "url": "http://example.test/api/members?id=1%27%20OR%201=1",
                    "status_code": 200,
                    "response_body": "[{\"id\":1}]",
                    "elapsed_ms": 12,
                },
                "metadata": {"verification_status": "VERIFIED"},
                "artifacts": [
                    {"kind": "baseline_evidence", "path": "baseline.png"},
                    {"kind": "attack_evidence", "path": "attack.png"},
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    output = tmp_path / "final"
    result = generate.generate_report(report_path, evidence_dir, output, include_pdf=False)

    assert result["ok"] is True
    assert result["findings"] == 1
    html = (output / "report.html").read_text(encoding="utf-8")
    step_1 = html.index("탐지 기법 및 테스트 방법")
    screenshot = html.index("data:image/png;base64", step_1)
    step_2 = html.index("진단 결과 및 취약 판정 근거", screenshot)
    step_3 = html.index("대응방안", step_2)
    assert step_1 < screenshot < step_2 < step_3
    assert "http://example.test/api/members" in html
    assert "SQL 질의문 삽입 취약점" in html
    assert "<h2>SQL Injection 취약점</h2>" not in html
    assert "grid-template-columns:1fr" in html
    assert "Prepared Statement" in html
    assert "SK Shieldus" not in html
    assert "SK 가이드라인" not in html
    assert (output / "report-data.json").is_file()
    assert (output / "report-manifest.json").is_file()


def test_g12_xss_guideline_uses_server_side_validation_wording():
    generate = _load_generate_module()
    guidance = generate.build_report.__globals__["guidance_for"]("xss")
    wording = " ".join(guidance.remediation)
    assert "서버 측" in wording
    assert "대·소문자를 구분하지 않는" in wording
