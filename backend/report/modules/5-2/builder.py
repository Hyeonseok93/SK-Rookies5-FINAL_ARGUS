"""5-2 진단 결과서(PDF) 생성기

data/report/5-2/latest.yaml (진단 결과) 와 evidence/evidence_manifest.json
(스크린샷 메타) 를 읽어 HTML 결과서를 만들고, Playwright(Chromium) 로 PDF 렌더링

결과물: data/report/5-2/5-2_diagnosis_report.pdf  (진단을 다시 하면 덮어쓴다)
"""

from __future__ import annotations

import base64
import html
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from . import content as C

logger = logging.getLogger(__name__)

SECTION_ID = "5-2"
SECTION_TITLE = "요청 및 응답 값 내 주요정보 포함여부 확인"
PDF_FILENAME = "5-2_diagnosis_report.pdf"


# ─────────────────────────────────────────────────────────────────────────
# 경로
# ─────────────────────────────────────────────────────────────────────────
def _report_dir(data_dir: Path) -> Path:
    return data_dir / "report" / SECTION_ID


def pdf_output_path(data_dir: Path) -> Path:
    return _report_dir(data_dir) / PDF_FILENAME


# ─────────────────────────────────────────────────────────────────────────
# 데이터 로드
# ─────────────────────────────────────────────────────────────────────────
def _load_latest(data_dir: Path) -> dict[str, Any]:
    path = _report_dir(data_dir) / "latest.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"5-2 진단 결과(latest.yaml)가 없습니다: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("latest.yaml 형식이 올바르지 않습니다.")
    return raw


def _load_manifest(data_dir: Path) -> dict[str, Any]:
    path = _report_dir(data_dir) / "evidence" / "evidence_manifest.json"
    if not path.is_file():
        return {"shots": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("evidence_manifest.json 파싱 실패: %s", path)
        return {"shots": []}


# ─────────────────────────────────────────────────────────────────────────
# 파싱 헬퍼
# ─────────────────────────────────────────────────────────────────────────
def _stats(latest: dict[str, Any]) -> dict[str, Any]:
    for f in latest.get("findings") or []:
        ev = f.get("evidence") or {}
        if isinstance(ev, dict) and "stats" in ev:
            return ev["stats"] or {}
    return {}


def _real_findings(latest: dict[str, Any]) -> list[dict[str, Any]]:
    """통계(info) 항목을 제외한 실제 노출 findings (collapsed)"""
    out: list[dict[str, Any]] = []
    for f in latest.get("findings") or []:
        ev = f.get("evidence") or {}
        if isinstance(ev, dict) and "stats" in ev:
            continue
        if str(f.get("severity", "")).lower() == "info":
            continue
        out.append(f)
    return out


def _account_from_auth_mode(mode: str) -> str:
    mode = (mode or "").strip()
    if mode in ("anonymous", "anon"):
        return "익명"
    # authenticated:email@x.com:login  →  email@x.com
    if mode.startswith("authenticated:"):
        parts = mode.split(":")
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    return mode or "-"


def _auth_label(ev: dict[str, Any]) -> str:
    modes = ev.get("auth_modes")
    if isinstance(modes, list) and modes:
        accounts = [_account_from_auth_mode(m) for m in modes]
    else:
        accounts = [_account_from_auth_mode(ev.get("auth_mode", ""))]
    # 중복 제거(순서 유지)
    seen: list[str] = []
    for a in accounts:
        if a not in seen:
            seen.append(a)
    has_anon = "익명" in seen
    named = [a for a in seen if a != "익명"]
    if has_anon and named:
        return f"익명 + {len(named)}계정"
    if has_anon:
        return "익명"
    if len(named) == 1:
        return named[0]
    return f"{named[0]} 외 {len(named) - 1}계정" if named else "-"


_KST = timezone(timedelta(hours=9))


def _fmt_datetime(value: str | None) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        dt = dt.astimezone(_KST)
        return dt.strftime("%Y-%m-%d %H:%M KST")
    except (ValueError, AttributeError):
        return value


def _techniques_used(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """실제 발견된 rule_id 로부터 사용된 탐지 기법을 매핑(중복 제거, 순서 유지)"""
    tech_ids: list[str] = []
    for f in findings:
        ev = f.get("evidence") or {}
        rule_id = str(ev.get("rule_id", ""))
        tech_id = C.RULE_TO_TECHNIQUE.get(rule_id)
        if tech_id and tech_id not in tech_ids:
            tech_ids.append(tech_id)
    return [C.TECHNIQUES[t] for t in tech_ids if t in C.TECHNIQUES]


def _image_data_uri(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:image/png;base64,{b64}"


# ─────────────────────────────────────────────────────────────────────────
# HTML 렌더링
# ─────────────────────────────────────────────────────────────────────────
def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


_CSS = """
* { box-sizing: border-box; }
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
body {
  font-family: "Noto Sans CJK KR", "Noto Sans KR", "Malgun Gothic", sans-serif;
  color: #1b2430; font-size: 11px; line-height: 1.55; margin: 0;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
.header {
  display: flex; align-items: center; gap: 14px;
  border-bottom: 3px solid #0ea5b7; padding-bottom: 14px; margin-bottom: 18px;
}
.header .logo { height: 40px; }
.header .titles { flex: 1; }
.badge-sec {
  display: inline-block; background: #0ea5b7; color: #fff; font-weight: 700;
  padding: 2px 8px; border-radius: 5px; font-size: 12px; margin-right: 8px;
}
.header h1 { font-size: 17px; margin: 0; color: #0b2b33; display: inline; }
.header .sub { color: #5b6b7a; font-size: 10.5px; margin-top: 6px; }
.status {
  display: inline-block; padding: 3px 12px; border-radius: 999px;
  font-weight: 700; font-size: 12px;
}
.status.fail { background: #fde8e8; color: #c0392b; border: 1px solid #f5b7b1; }
.status.pass { background: #e8f8f0; color: #1e8449; border: 1px solid #a9dfbf; }
.summary {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 4px 0 20px;
}
.summary .cell {
  background: #f4f8fb; border: 1px solid #dbe7ef; border-radius: 8px;
  padding: 9px 10px; text-align: center;
}
.summary .cell .n { font-size: 18px; font-weight: 800; color: #0b6b78; }
.summary .cell .l { font-size: 9.5px; color: #5b6b7a; margin-top: 2px; }
h2 {
  font-size: 14px; color: #0b2b33; border-left: 5px solid #0ea5b7;
  padding-left: 9px; margin: 24px 0 12px;
}
h2 .step { color: #0ea5b7; font-weight: 800; margin-right: 6px; }
.lead { color: #45535f; margin: 0 0 12px; }
.note {
  background: #fff8ec; border: 1px solid #f3dfb0; border-radius: 8px;
  padding: 9px 12px; margin: 0 0 12px; font-size: 10px; color: #5f5330;
}
.note p { margin: 0 0 6px; }
.note p:last-child { margin-bottom: 0; }
.note b { color: #8a6d1f; }
.tech {
  border: 1px solid #dbe7ef; border-radius: 8px; padding: 11px 13px;
  margin-bottom: 9px; background: #fbfdff; break-inside: avoid;
}
.tech .t { font-weight: 700; font-size: 12px; color: #0b6b78; }
.tech .s { color: #33414d; margin: 3px 0 5px; font-size: 10.5px; }
.tech .d { color: #5b6b7a; font-size: 10px; }
.tech.probe { background: #eef8fa; border-color: #b9e3ea; }
table.findings {
  width: 100%; border-collapse: collapse; font-size: 9.5px; margin-bottom: 8px;
}
table.findings th {
  background: #0b6b78; color: #fff; text-align: left; padding: 6px 7px;
  font-weight: 600; font-size: 9.5px;
}
table.findings td {
  border-bottom: 1px solid #e3ecf2; padding: 5px 7px; vertical-align: top;
  word-break: break-all;
}
table.findings tr:nth-child(even) td { background: #f7fafc; }
.sev { font-weight: 700; padding: 1px 6px; border-radius: 4px; font-size: 9px; white-space: nowrap; }
.sev.high { background: #fde8e8; color: #c0392b; }
.sev.medium { background: #fef5e7; color: #b9770e; }
.sev.low { background: #eaf2fb; color: #2471a3; }
.mono { font-family: "Consolas", "D2Coding", monospace; }
.muted { color: #8595a3; }
.ev-grid { margin-top: 8px; }
.ev-card {
  border: 1px solid #dbe7ef; border-radius: 8px; overflow: hidden;
  margin-bottom: 12px; break-inside: avoid;
}
.ev-card .cap {
  background: #f4f8fb; padding: 6px 10px; font-size: 9.5px; color: #33414d;
  border-bottom: 1px solid #dbe7ef; display: flex; gap: 8px; align-items: center;
}
.ev-card .cap .seq {
  background: #0b6b78; color: #fff; border-radius: 4px; padding: 1px 6px; font-weight: 700;
}
.ev-card img { display: block; width: 100%; }
.ev-card .meta { padding: 5px 10px; font-size: 9px; color: #5b6b7a; }
.remediation {
  background: #eef8fa; border: 1px solid #b9e3ea; border-radius: 10px; padding: 14px 16px;
}
.remediation p { margin: 0 0 10px; color: #22333f; }
.remediation p:last-child { margin-bottom: 0; }
.remediation .src { color: #5b6b7a; font-size: 9.5px; margin-top: 4px; }
.footer { margin-top: 22px; border-top: 1px solid #dbe7ef; padding-top: 8px;
  color: #8595a3; font-size: 9px; text-align: center; }
.empty { color: #1e8449; background: #e8f8f0; border: 1px solid #a9dfbf;
  border-radius: 8px; padding: 12px 14px; }
"""


def _render_summary(stats: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    cov = stats.get("coverage") or {}
    cells = [
        (stats.get("endpoints_probed", stats.get("endpoints_total", "-")), "점검 엔드포인트"),
        (stats.get("issues", len(findings)), "노출 항목"),
        (cov.get("responses_with_body", "-"), "응답 본문 수집"),
        (cov.get("status_2xx", "-"), "정상 응답(2xx)"),
    ]
    html_cells = "".join(
        f'<div class="cell"><div class="n">{_esc(n)}</div><div class="l">{_esc(l)}</div></div>'
        for n, l in cells
    )
    return f'<div class="summary">{html_cells}</div>'


def _render_techniques(techniques: list[dict[str, str]]) -> str:
    blocks = [
        '<div class="tech probe">'
        f'<div class="t">{_esc(C.PROBING_OVERVIEW["title"])}</div>'
        f'<div class="s">{_esc(C.PROBING_OVERVIEW["summary"])}</div>'
        f'<div class="d">{_esc(C.PROBING_OVERVIEW["detail"])}</div>'
        "</div>"
    ]
    if techniques:
        for t in techniques:
            blocks.append(
                '<div class="tech">'
                f'<div class="t">{_esc(t["title"])}</div>'
                f'<div class="s">{_esc(t["summary"])}</div>'
                f'<div class="d">{_esc(t["detail"])}</div>'
                "</div>"
            )
    return "".join(blocks)


def _render_findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return (
            '<div class="empty">요청·응답에 마스킹 없이 노출된 개인정보가 발견되지 '
            "않았습니다. 조치가 필요한 항목이 없습니다.</div>"
        )
    rows: list[str] = []
    # 심각도 우선 정렬(high → medium → low)
    order = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(
        findings,
        key=lambda f: order.get(str(f.get("severity", "")).lower(), 9),
    )
    for f in ordered:
        ev = f.get("evidence") or {}
        sev = str(f.get("severity", "")).lower()
        method = _esc(ev.get("method", ""))
        url = _esc(ev.get("url", ""))
        cat = _esc(C.category_ko(ev.get("category")))
        loc = _esc(C.direction_ko(ev.get("direction")))
        field = _esc(ev.get("field_path", ""))
        auth = _esc(_auth_label(ev))
        rows.append(
            "<tr>"
            f'<td><span class="mono">{method}</span><br>'
            f'<span class="mono muted">{url}</span></td>'
            f"<td>{cat}</td>"
            f'<td>{loc}<br><span class="mono muted">{field}</span></td>'
            f"<td>{auth}</td>"
            f'<td><span class="sev {sev}">{_esc(C.severity_ko(sev))}</span></td>'
            "</tr>"
        )
    return (
        '<table class="findings"><thead><tr>'
        "<th>API (URL)</th><th>유형</th><th>위치</th><th>인증</th><th>심각도</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _render_evidence(data_dir: Path, manifest: dict[str, Any]) -> str:
    shots = manifest.get("shots") or []
    evidence_dir = _report_dir(data_dir) / "evidence"
    cards: list[str] = []
    for shot in shots:
        fname = shot.get("file")
        if not fname:
            continue
        uri = _image_data_uri(evidence_dir / fname)
        if not uri:
            continue
        seq = _esc(shot.get("seq", ""))
        endpoint = _esc(shot.get("endpoint_id", ""))
        kind = "응답" if shot.get("kind") == "response" else "요청"
        account = _esc(shot.get("account", ""))
        cats = ", ".join(C.category_ko(c) for c in (shot.get("categories") or []))
        fields = ", ".join(shot.get("field_paths") or [])
        cards.append(
            '<div class="ev-card">'
            f'<div class="cap"><span class="seq">{seq}</span>'
            f'<span class="mono">{endpoint}</span></div>'
            f'<img src="{uri}" alt="evidence {seq}"/>'
            f'<div class="meta">유형: {_esc(cats)} · 위치: {kind} 본문 · 계정: {account}'
            + (f' · 필드: <span class="mono">{_esc(fields)}</span>' if fields else "")
            + "</div>"
            "</div>"
        )
    if not cards:
        return '<p class="muted">첨부된 증거 스크린샷이 없습니다.</p>'
    return '<div class="ev-grid">' + "".join(cards) + "</div>"


def _render_remediation() -> str:
    paras = "".join(f"<p>{_esc(p)}</p>" for p in C.REMEDIATION_PARAGRAPHS)
    return f'<div class="remediation">{paras}</div>'


def _logo_data_uri() -> str | None:
    # frontend/src/assets/argus_logo.png 를 백엔드 기준 상대 경로로 탐색
    here = Path(__file__).resolve()
    # backend/report/modules/5-2/builder.py → backend
    backend_root = here.parents[3]
    candidates = [
        backend_root.parent / "frontend" / "src" / "assets" / "argus_logo.png",
        backend_root / "data" / "report" / "5-2" / "argus_logo.png",
    ]
    for c in candidates:
        if c.is_file():
            uri = _image_data_uri(c)
            if uri:
                return uri
    return None


def render_html(data_dir: Path) -> str:
    latest = _load_latest(data_dir)
    manifest = _load_manifest(data_dir)
    stats = _stats(latest)
    findings = _real_findings(latest)
    techniques = _techniques_used(findings)

    status = str(latest.get("status", "")).lower()
    status_cls = "fail" if status == "fail" else "pass"
    status_label = "취약 (FAIL)" if status == "fail" else "양호 (PASS)"
    checked_at = _fmt_datetime(latest.get("checked_at"))

    logo_uri = _logo_data_uri()
    logo_html = f'<img class="logo" src="{logo_uri}" alt="ARGUS"/>' if logo_uri else ""

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><style>{_CSS}</style></head>
<body>
  <div class="header">
    {logo_html}
    <div class="titles">
      <div><span class="badge-sec">{_esc(SECTION_ID)}</span>
        <h1>{_esc(SECTION_TITLE)}</h1></div>
      <div class="sub">자동 진단 결과서 · 점검 시각 {checked_at}</div>
    </div>
    <div class="status {status_cls}">{_esc(status_label)}</div>
  </div>

  {_render_summary(stats, findings)}

  <h2><span class="step">1.</span>탐지 기법 및 테스트 방법</h2>
  <p class="lead">아래 탐지 기법으로 요청·응답 값을 점검했습니다.</p>
  {_render_techniques(techniques)}

  <h2><span class="step">2.</span>진단 결과</h2>
  <p class="lead">점검 대상 API에서 아래와 같이 개인정보가 마스킹 없이 노출되었습니다.
     (실제 노출 URL 포함)</p>
  <div class="note">
    <p><b>익명</b> — 로그인 토큰이나 세션(인증 정보) 없이 보낸 요청을 뜻합니다.
       익명 상태에서도 노출된 항목은 <b>로그인하지 않은 사용자도 개인정보를 볼 수 있음</b>을
       의미하므로 더 위험합니다. (예: <span class="mono">익명 + 3계정</span> = 익명 및
       테스트 계정 3개 모두에서 동일하게 노출)</p>
    <p><b>경로·구조</b> 유형 — URL 주소나 응답 값에 서버 내부 경로·파일 구조가 노출된
       경우로, 표의 위치 외에 아래 <b>증거 스크린샷의 URL 영역</b>에서 실제 노출 지점을
       함께 확인할 수 있습니다.</p>
  </div>
  {_render_findings_table(findings)}
  {_render_evidence(data_dir, manifest)}

  <h2><span class="step">3.</span>{_esc(C.REMEDIATION_TITLE)}</h2>
  {_render_remediation()}

  <div class="footer">ARGUS 자동 진단 시스템 · 본 결과서는 진단 실행 시점의 데이터를 기준으로 자동 생성되었습니다.</div>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────
# PDF 렌더링
# ─────────────────────────────────────────────────────────────────────────
def _html_to_pdf(html_str: str, out_path: Path) -> None:
    from playwright.sync_api import sync_playwright

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = browser.new_page()
            page.set_content(html_str, wait_until="load")
            page.pdf(
                path=str(out_path),
                format="A4",
                print_background=True,
                margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
            )
        finally:
            browser.close()


def build_report(data_dir: Path) -> Path:
    """5-2 진단 결과서 PDF 를 생성(덮어쓰기)하고 경로를 반환"""
    html_str = render_html(data_dir)
    out_path = pdf_output_path(data_dir)
    _html_to_pdf(html_str, out_path)
    logger.info("5-2 결과서 생성 완료: %s", out_path)
    return out_path
