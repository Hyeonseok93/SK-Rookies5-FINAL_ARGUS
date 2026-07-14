"""PDF report renderer for section 6-1 (오류페이지를 통한 정보 노출 여부).

Fully self-contained — owns the whole 6-1 report-PDF pipeline (summary
lookup, HTML/CSS, Playwright printing, persisting to latest.pdf) with no
dependency on any shared/common report module. Every other module writes its
own report generation code the same way.

6-1 stores tens of thousands of raw findings, so this renders the aggregated
group summary (``diagnosis/modules/6-1/report_summary.py``) that the dashboard
already uses, never the raw latest.yaml — looping over ~74k rows would make
the PDF unusable.

Page layout (cover → executive summary → item matrix → detail → evidence
appendix → methodology) follows the approved report template
(``argus-report-6-1.html`` format draft) — every value below is pulled from
the real report/evidence data, nothing is sample/placeholder content.

The running header/footer (report number, "Confidential", page X / Y) is
rendered by Playwright's native ``header_template``/``footer_template`` in
the page margin, not hand-rolled DOM elements — a per-section header/footer
built with ``display: flex`` reliably produced a blank orphan page after
every section when Chromium had to fragment that flex box across a page
boundary (a known Chromium print-pagination bug), so the layout below sticks
to plain block flow inside each ``.sheet`` and lets ``break-after: page``
mark section boundaries.

Loaded dynamically by the router via
``importlib.util.spec_from_file_location`` (this folder is named "6-1", which
isn't a valid Python import segment — same convention as
diagnosis/modules/6-1 and screenshot/modules/6-1).
"""

from __future__ import annotations

import base64
import html as html_mod
from pathlib import Path
from typing import Any

from diagnosis.context import DiagnosisContext

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_TILE_ORDER = [("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")]

_FONT_SANS = (
    '"Pretendard Variable", Pretendard, "Noto Sans KR", "Noto Sans CJK KR", -apple-system, '
    'BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "Apple SD Gothic Neo", sans-serif'
)
_FONT_MONO = '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Noto Sans Mono", monospace'

_GUIDELINE_LABEL = "SK Shielders 웹/API 개발보안 진단 가이드라인"


def esc(value: object) -> str:
    return html_mod.escape(str(value if value is not None else ""))


def image_data_uri(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return f"data:image/png;base64,{base64.b64encode(raw).decode('ascii')}"


def status_badge(status: str) -> str:
    label = {
        "pass": "PASS",
        "fail": "FAIL",
        "warn": "WARN",
        "warning": "WARN",
        "error": "ERROR",
        "skipped": "SKIPPED",
        "not_implemented": "미구현",
        "not_diagnosable": "수동 검토",
        "pending": "PENDING",
        "no_targets": "대상 없음",
    }.get(status, status.upper())
    cls = {
        "pass": "pass",
        "fail": "fail",
        "warn": "warn",
        "warning": "warn",
        "error": "fail",
        "pending": "pending",
    }.get(status, "pending")
    return f'<span class="badge status-{cls}">{esc(label)}</span>'


def severity_badge(sev: str) -> str:
    sev = (sev or "info").lower()
    if sev not in _SEVERITY_RANK:
        sev = "info"
    return f'<span class="badge sev-{sev}">{esc(sev.upper())}</span>'


# ---------------------------------------------------------------------------
# Print CSS — this document is only ever rendered to a PDF (never viewed as a
# live page). The running header/footer live in Playwright's native page
# margin (see _print_pdf), so every section here is plain block content
# inside a ``.sheet`` — no flex on anything that might need to fragment
# across a page boundary.
# ---------------------------------------------------------------------------
_PRINT_CSS = f"""
* {{ box-sizing: border-box; }}
:root {{
  --paper: #f7f8f7; --paper-raised: #ffffff; --ink: #12161f; --ink-soft: #454e59;
  --muted: #6b7480; --line: #d9dfe3; --line-strong: #b7c0c7;
  --cover-bg: #0a1119; --cover-bg2: #0d1b26; --cover-ink: #eef3f5; --cover-muted: #9fb4bd;
  --accent: #0f7a8c; --accent-soft: #0f7a8c14;
  --sev-high: #b0261f; --sev-high-bg: #b0261f14;
  --sev-medium: #a15c06; --sev-medium-bg: #a15c0614;
  --sev-low: #2c5f9e; --sev-low-bg: #2c5f9e14;
  --sev-info: #6b7480; --sev-info-bg: #6b748014;
}}
html, body {{ margin: 0; background: #fff; color: var(--ink); font-family: {_FONT_SANS}; font-size: 13px; line-height: 1.6; }}

.sheet {{ break-after: page; }}
.sheet:last-child {{ break-after: auto; }}

/* cover — printed as its own document with zero margin (see _print_cover_pdf)
   so the background can bleed all the way to the paper edge, then merged in
   front of the header/footer'd content pages. */
.cover-card {{ width: 210mm; height: 297mm; padding: 40mm 24mm 24mm;
  background: radial-gradient(880px 460px at 82% -6%, #123443 0%, transparent 60%),
  linear-gradient(165deg, var(--cover-bg) 0%, var(--cover-bg2) 100%); color: var(--cover-ink); }}
.cover-eyebrow {{ font-family: {_FONT_MONO}; font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase;
  color: #6fd6e6; }}
.cover-eyebrow .rule {{ display: inline-block; width: 34px; height: 1px; background: #6fd6e6; opacity: 0.6; margin-right: 10px; vertical-align: middle; }}
.cover-title {{ margin: 22px 0 0; font-size: 34px; font-weight: 800; line-height: 1.25; letter-spacing: -0.01em; max-width: 18ch; }}
.cover-sub {{ margin: 16px 0 0; font-size: 13.5px; color: var(--cover-muted); max-width: 48ch; line-height: 1.75; }}
.cover-meta {{ margin-top: 34px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px 40px;
  max-width: 560px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.14); }}
.cover-meta dt {{ font-family: {_FONT_MONO}; font-size: 9.5px; letter-spacing: 0.08em; text-transform: uppercase; color: #6f8794; }}
.cover-meta dd {{ margin: 3px 0 0; font-size: 12.5px; font-weight: 600; color: var(--cover-ink); word-break: break-all; }}
.cover-classification {{ margin-top: 28px; display: inline-block; padding: 7px 13px; border: 1px solid #b6482f;
  border-radius: 3px; background: #b6482f1c; color: #ff9a7c; font-family: {_FONT_MONO}; font-size: 10.5px;
  letter-spacing: 0.08em; text-transform: uppercase; font-weight: 700; }}

/* shared page furniture */
.kicker {{ font-family: {_FONT_MONO}; font-size: 10.5px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); font-weight: 700; }}
h2.page-title {{ margin: 4px 0 20px; font-size: 22px; font-weight: 800; letter-spacing: -0.005em; color: var(--ink); }}
h3.section-title {{ margin: 26px 0 12px; font-size: 14px; font-weight: 700; color: var(--ink); padding-bottom: 8px; border-bottom: 1px solid var(--line); break-after: avoid; }}
h3.section-title:first-child {{ margin-top: 0; }}
p.lede {{ color: var(--ink-soft); max-width: 66ch; }}

.stat-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 4px; break-inside: avoid; }}
.stat-tile {{ border: 1px solid var(--line); border-radius: 4px; padding: 12px 14px; background: var(--paper-raised); }}
.stat-tile .n {{ font-family: {_FONT_MONO}; font-variant-numeric: tabular-nums; font-size: 24px; font-weight: 700; line-height: 1; }}
.stat-tile .l {{ margin-top: 7px; font-size: 10.5px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); }}
.stat-tile.high .n {{ color: var(--sev-high); }}
.stat-tile.medium .n {{ color: var(--sev-medium); }}
.stat-tile.low .n {{ color: var(--sev-low); }}
.stat-tile.info .n {{ color: var(--sev-info); }}

.risk-banner {{ margin-top: 18px; padding: 14px 18px; border: 1px solid var(--sev-high); border-left-width: 4px;
  border-radius: 3px; background: var(--sev-high-bg); break-inside: avoid; }}
.risk-banner .level {{ font-family: {_FONT_MONO}; font-size: 16px; font-weight: 800; color: var(--sev-high);
  margin-right: 14px; }}
.risk-banner .desc {{ font-size: 11.5px; color: var(--ink-soft); line-height: 1.6; }}
.risk-banner .desc b {{ color: var(--ink); }}

table.report-table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
table.report-table thead {{ display: table-header-group; }}
table.report-table th {{ text-align: left; font-family: {_FONT_MONO}; font-size: 9.5px; letter-spacing: 0.05em;
  text-transform: uppercase; color: var(--muted); font-weight: 600; padding: 0 8px 7px; border-bottom: 1px solid var(--line-strong);
  background: var(--paper); }}
table.report-table td {{ padding: 8px; border-bottom: 1px solid var(--line); vertical-align: top; color: var(--ink-soft); }}
table.report-table tr {{ break-inside: avoid; }}
table.report-table td:first-child, table.report-table th:first-child {{ padding-left: 0; }}
table.report-table td:last-child, table.report-table th:last-child {{ padding-right: 0; }}
table.report-table tr.chapter-row td {{ padding-top: 14px; font-family: {_FONT_MONO}; font-size: 9.5px; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--accent); font-weight: 700; border-bottom: none; }}
table.report-table td.id {{ font-family: {_FONT_MONO}; color: var(--ink); white-space: nowrap; }}
table.report-table td.title {{ color: var(--ink); }}
table.report-table td.num {{ font-family: {_FONT_MONO}; font-variant-numeric: tabular-nums; text-align: right; }}

.badge {{ display: inline-block; font-family: {_FONT_MONO}; font-size: 9px; font-weight: 700;
  text-transform: uppercase; padding: 2px 7px; border-radius: 999px; border: 1px solid currentColor;
  white-space: nowrap; text-align: center; }}
.badge.status-fail {{ color: var(--sev-high); background: var(--sev-high-bg); }}
.badge.status-warn {{ color: var(--sev-medium); background: var(--sev-medium-bg); }}
.badge.status-pass {{ color: #1f6b45; background: #1f6b4514; }}
.badge.status-pending {{ color: var(--muted); background: #6b748014; }}
.badge.sev-high {{ color: var(--sev-high); background: var(--sev-high-bg); }}
.badge.sev-medium {{ color: var(--sev-medium); background: var(--sev-medium-bg); }}
.badge.sev-low {{ color: var(--sev-low); background: var(--sev-low-bg); }}
.badge.sev-info {{ color: var(--sev-info); background: var(--sev-info-bg); }}

.stats-strip {{ display: flex; flex-wrap: wrap; gap: 6px 16px; padding: 10px 13px; margin-bottom: 16px;
  background: var(--paper-raised); border: 1px solid var(--line); border-radius: 4px; font-family: {_FONT_MONO};
  font-size: 10.5px; color: var(--ink-soft); break-inside: avoid; }}
.stats-strip b {{ color: var(--ink); }}

.finding {{ border: 1px solid var(--line); border-radius: 4px; margin-bottom: 12px; overflow: hidden; break-inside: avoid; }}
.finding-head {{ display: flex; align-items: center; gap: 10px; padding: 10px 13px; background: var(--paper-raised); border-bottom: 1px solid var(--line); flex-wrap: wrap; }}
.finding-head .msg {{ font-size: 12px; font-weight: 600; color: var(--ink); }}
.finding-body {{ padding: 12px 13px; }}
.kv-grid {{ display: grid; grid-template-columns: 108px 1fr; gap: 5px 10px; font-size: 11px; }}
.kv-grid dt {{ color: var(--muted); margin: 0; }}
.kv-grid dd {{ margin: 0; font-family: {_FONT_MONO}; color: var(--ink-soft); word-break: break-all; }}

.step-list {{ margin-top: 10px; }}
.step-item {{ padding-top: 10px; margin-top: 10px; border-top: 1px dashed var(--line); break-inside: avoid; }}
.step-item:first-child {{ padding-top: 0; margin-top: 0; border-top: none; }}
.step-label {{ font-size: 10px; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; color: var(--accent);
  margin-bottom: 5px; }}
.step-label .num {{ display: inline-flex; align-items: center; justify-content: center; width: 15px; height: 15px;
  border-radius: 999px; background: var(--accent); color: var(--paper); font-family: {_FONT_MONO}; font-size: 9px;
  font-weight: 700; margin-right: 6px; }}
.step-body {{ font-size: 11.5px; line-height: 1.7; color: var(--ink-soft); }}
.step-body .url {{ display: block; margin-top: 5px; font-family: {_FONT_MONO}; font-size: 10px; color: var(--ink);
  background: var(--accent-soft); padding: 3px 6px; border-radius: 2px; word-break: break-all; }}
.step-item.reco .step-label {{ color: #1f6b45; }}
.step-item.reco .step-label .num {{ background: #1f6b45; }}
.step-item.reco .step-body {{ color: #1f6b45; }}

.evidence-img {{ margin-top: 10px; break-inside: avoid; }}
.evidence-img img {{ max-width: 100%; border: 1px solid var(--line); border-radius: 3px; display: block; }}
.evidence-img .cap {{ margin-top: 4px; font-family: {_FONT_MONO}; font-size: 9px; color: var(--muted); }}

.evidence-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }}
.evidence-thumb {{ border: 1px solid var(--line); border-radius: 4px; overflow: hidden; break-inside: avoid; }}
.evidence-thumb .art {{ background: #111315; }}
.evidence-thumb .art img {{ width: 100%; display: block; }}
.evidence-thumb .cap {{ padding: 8px 10px; }}
.evidence-thumb .cap .t {{ font-size: 10.5px; font-weight: 600; color: var(--ink); }}
.evidence-thumb .cap .p {{ margin-top: 3px; font-family: {_FONT_MONO}; font-size: 8.8px; color: var(--muted); word-break: break-all; }}
.evidence-thumb .cap .v {{ margin-top: 3px; font-size: 9.5px; }}
.evidence-thumb .cap .v.ok {{ color: #1f6b45; }}
.evidence-thumb .cap .v.miss {{ color: var(--muted); }}

.def-list {{ display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; font-size: 11.5px; }}
.def-list dt {{ font-family: {_FONT_MONO}; }}
.def-list dd {{ margin: 0; color: var(--ink-soft); }}
.def-list > dt, .def-list > dd {{ break-inside: avoid; }}

.callout {{ margin-top: 14px; padding: 12px 14px; border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: 3px; background: var(--accent-soft); font-size: 11.5px; color: var(--ink-soft); line-height: 1.65;
  break-inside: avoid; }}
.callout b {{ color: var(--ink); }}

.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }}
"""

_HEADER_TEMPLATE = """
<div style="width:100%; font-size:8px; font-family:ui-monospace,Menlo,monospace;
  color:#6b7480; padding:0 16mm; display:flex; justify-content:space-between;">
  <span>ARGUS · 웹/API 개발보안 진단 보고서</span>
  <span class="report-no"></span>
</div>
"""

_FOOTER_TEMPLATE = """
<div style="width:100%; font-size:8px; font-family:ui-monospace,Menlo,monospace;
  color:#6b7480; padding:0 16mm; display:flex; justify-content:space-between;">
  <span>Confidential · ARGUS Diagnosis Engine</span>
  <span><span class="pageNumber"></span> / <span class="totalPages"></span></span>
</div>
"""


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _app_name(raw_config: dict[str, Any]) -> str:
    return str(raw_config.get("app_name") or "").strip()


def _load_raw_config() -> dict[str, Any]:
    import os

    import yaml

    from app.config import BACKEND_ROOT

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    if config_path.is_file():
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return {}


# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------
def _cover_page(*, section_id: str, title: str, checked_at: str | None,
                 base_urls: list[str], app_name: str, report_no: str, generated_at: str) -> str:
    target = f"{app_name} · {', '.join(base_urls)}" if app_name else (", ".join(base_urls) or "—")
    checked = esc(checked_at) if checked_at else "—"
    return f"""
<section class="sheet">
  <div class="cover-card">
    <div class="cover-eyebrow"><span class="rule"></span>Web · API Secure-Coding Diagnosis Report</div>
    <h1 class="cover-title">웹·API 개발보안<br/>취약점 진단 보고서</h1>
    <p class="cover-sub">
      {esc(_GUIDELINE_LABEL)} 기준, <b>{esc(section_id)} {esc(title)}</b> 항목에 대한
      ARGUS 자동 진단 엔진(httpx · Playwright)의 실행 결과와 증거 자료를 정리한 보고서입니다.
    </p>
    <dl class="cover-meta">
      <div><dt>진단 대상</dt><dd>{esc(target)}</dd></div>
      <div><dt>진단 항목</dt><dd>{esc(section_id)} · {esc(title)}</dd></div>
      <div><dt>진단 기준</dt><dd>{esc(_GUIDELINE_LABEL)}</dd></div>
      <div><dt>진단(스캔) 일시</dt><dd>{checked}</dd></div>
      <div><dt>보고서 번호</dt><dd>{esc(report_no)}</dd></div>
      <div><dt>보고서 생성</dt><dd>{esc(generated_at)}</dd></div>
    </dl>
    <div class="cover-classification">Confidential · 내부 검토용</div>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------
def _stat_tiles_html(by_severity: dict[str, Any]) -> str:
    tiles = []
    for key, label in _SEVERITY_TILE_ORDER:
        n = int(by_severity.get(key, 0) or 0)
        tiles.append(f'<div class="stat-tile {key}"><div class="n">{n:,}</div><div class="l">{esc(label)}</div></div>')
    return f'<div class="stat-row">{"".join(tiles)}</div>'


def _risk_banner_html(groups: list[dict[str, Any]]) -> str:
    if not groups:
        return ""
    top = groups[0]
    sev = str(top.get("severity") or "info").upper()
    origin = str(top.get("origin") or "-")
    rule_label = str(top.get("rule_label") or "")
    count = int(top.get("count") or 0)
    sample_urls = list(top.get("sample_urls") or [])
    url_hint = f" ( <code style=\"font-family:{_FONT_MONO}\">{esc(sample_urls[0])}</code> 등 )" if sample_urls else ""
    return f"""
<div class="risk-banner">
  <span class="level">{esc(sev)}</span>
  <span class="desc">
    <b>종합 위험도: {esc(sev)}.</b> {esc(origin)}에서 <b>{esc(rule_label)}</b> 패턴이
    총 <b>{count:,}건</b> 발견되었습니다{url_hint} — 상세 근거는 상세 진단 페이지를 참고하십시오.
  </span>
</div>"""


def _pattern_rows(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate the per-origin groups into one row per rule_id for the summary table."""
    agg: dict[str, dict[str, Any]] = {}
    for g in groups:
        rid = str(g.get("rule_id") or "unknown")
        row = agg.setdefault(
            rid,
            {
                "rule_id": rid,
                "rule_label": g.get("rule_label"),
                "category_label": g.get("category_label"),
                "severity": g.get("severity"),
                "count": 0,
            },
        )
        row["count"] += int(g.get("count") or 0)
        if _SEVERITY_RANK.get(str(g.get("severity")), 0) > _SEVERITY_RANK.get(str(row["severity"]), 0):
            row["severity"] = g.get("severity")
    rows = list(agg.values())
    rows.sort(key=lambda r: (-_SEVERITY_RANK.get(str(r["severity"]), 0), -int(r["count"])))
    return rows


def _confidence_label(severity: str) -> str:
    return "확정" if str(severity).lower() == "high" else "진단자 확인 필요"


def _pattern_table_html(groups: list[dict[str, Any]]) -> str:
    rows = _pattern_rows(groups)
    body = []
    for r in rows:
        body.append(
            "<tr>"
            f'<td class="id">{esc(r["rule_id"])}</td>'
            f"<td>{severity_badge(str(r['severity']))}</td>"
            f'<td class="num">{int(r["count"]):,}</td>'
            f"<td>{esc(r['category_label'])} · {esc(r['rule_label'])} — {esc(_confidence_label(r['severity']))}</td>"
            "</tr>"
        )
    return f"""
<table class="report-table">
  <thead><tr><th>Rule</th><th style="width:64px">심각도</th><th style="width:70px" class="num">건수</th><th>요약</th></tr></thead>
  <tbody>{"".join(body)}</tbody>
</table>"""


def _summary_page(*, section_id: str, summary: dict[str, Any], stats: dict[str, Any],
                   checked_at: str | None) -> str:
    total = int(summary.get("total_issues") or 0)
    by_severity = dict(summary.get("by_severity") or {})
    groups = list(summary.get("groups") or [])
    n_patterns = len(_pattern_rows(groups))

    endpoints = stats.get("endpoints_probed")
    requests_sent = stats.get("requests_sent")
    raw_leaks = stats.get("raw_leaks")
    collapsed = stats.get("collapsed_leaks")
    review_items = stats.get("review_items")

    return f"""
<section class="sheet">
  <span class="kicker">01 · Executive Summary</span>
  <h2 class="page-title">{esc(section_id)} 진단 결과 요약</h2>
  <p class="lede">
    <b>{esc(section_id)}</b> 항목에 대한 진단 결과, 총 <b>{total:,}건</b>의 정보 노출 finding이
    {n_patterns}개 패턴으로 그룹핑되어 확인되었습니다
    {f"(원본 {int(raw_leaks):,}건 → 중복 제거 {int(collapsed):,}건)" if raw_leaks and collapsed else ""}.
  </p>

  {_risk_banner_html(groups)}
  {_stat_tiles_html(by_severity)}

  <h3 class="section-title">항목 정보</h3>
  <dl class="def-list" style="grid-template-columns:120px 1fr;">
    <dt>진단 항목</dt><dd>{esc(section_id)}</dd>
    <dt>대상 엔드포인트</dt><dd>{esc(endpoints) if endpoints is not None else "—"}개</dd>
    <dt>전송 요청 수</dt><dd>{f"{int(requests_sent):,}건" if requests_sent is not None else "—"}</dd>
    <dt>finding 수</dt><dd>{total:,}건 · {n_patterns}개 패턴</dd>
    {f"<dt>진단자 확인 필요</dt><dd>{int(review_items):,}건</dd>" if review_items is not None else ""}
    <dt>checked_at</dt><dd>{esc(checked_at) if checked_at else "—"}</dd>
  </dl>

  <h3 class="section-title">발견 패턴 요약 ({n_patterns}개)</h3>
  {_pattern_table_html(groups)}

  <div class="callout">
    <b>진단 방법.</b> httpx 자동 프로브(파라미터·바디·경로·메서드·헤더 트리거)로 대상 엔드포인트에
    비정상 입력을 주입해 오류 응답을 수집·분석했습니다. 상세 방법론은 방법론 페이지를 참고하십시오.
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Item matrix (this renderer only ever covers its own module)
# ---------------------------------------------------------------------------
def _matrix_page(*, section_id: str, title: str, chapter: int, status: str,
                  top_severity: str, total: int) -> str:
    return f"""
<section class="sheet">
  <span class="kicker">02 · Item Overview</span>
  <h2 class="page-title">진단 항목 개요</h2>
  <p class="lede">{esc(_GUIDELINE_LABEL)}의 진단 항목 중, 본 보고서는 <b>{esc(section_id)}</b> 항목으로
  범위를 한정합니다. finding 수는 <code style="font-family:{_FONT_MONO}">data/report/{esc(section_id)}/latest.yaml</code>의 실제 값입니다.</p>

  <table class="report-table">
    <thead>
      <tr><th style="width:40px">항목</th><th>진단명</th><th style="width:64px">상태</th><th style="width:92px">최고 심각도</th><th style="width:64px" class="num">finding</th></tr>
    </thead>
    <tbody>
      <tr class="chapter-row"><td colspan="5">Chapter {chapter}</td></tr>
      <tr>
        <td class="id">{esc(section_id)}</td>
        <td class="title">{esc(title)}</td>
        <td>{status_badge(status)}</td>
        <td>{severity_badge(top_severity)}</td>
        <td class="num">{total:,}</td>
      </tr>
    </tbody>
  </table>

  <div class="callout">
    <b>범위 안내.</b> 본 보고서는 {esc(_GUIDELINE_LABEL)}의 전체 진단 항목 중 {esc(section_id)} 항목 단독 결과입니다.
    전체 항목에 대한 진단 현황은 별도의 전체 보고서(대시보드)를 참고하십시오.
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Affected endpoint inventory — every endpoint that produced at least one
# finding (not a sample), aggregated from the full raw findings via
# endpoint_id (diagnosis/modules/6-1/report_summary.py). The table is one
# continuous <table> and is allowed to flow across as many physical pages as
# it needs — the CSS repeats <thead> on each page (table-header-group) and
# keeps each <tr> intact (break-inside: avoid).
# ---------------------------------------------------------------------------
def _endpoint_inventory_page(*, section_id: str, endpoints: list[dict[str, Any]]) -> str:
    rows = []
    for i, ep in enumerate(endpoints, start=1):
        total_patterns = int(ep.get("total_patterns") or 0)
        matched = int(ep.get("matched_patterns") or 0)
        rows.append(
            "<tr>"
            f'<td class="num">{i}</td>'
            f'<td class="id">{esc(ep.get("method"))}</td>'
            f'<td class="title" style="font-family:{_FONT_MONO}; font-size:10px;">{esc(ep.get("path"))}</td>'
            f"<td>{severity_badge(str(ep.get('severity') or 'info'))}</td>"
            f'<td class="num">{matched}/{total_patterns}</td>'
            f'<td class="num">{int(ep.get("count") or 0):,}</td>'
            "</tr>"
        )

    body = (
        f"""<table class="report-table">
    <thead>
      <tr><th style="width:28px">#</th><th style="width:52px">Method</th><th>URL (path)</th>
      <th style="width:80px">최고 심각도</th><th style="width:74px" class="num">매칭 패턴</th>
      <th style="width:78px" class="num">finding 건수</th></tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>"""
        if rows
        else '<p class="lede">취약점이 발견된 엔드포인트가 없습니다.</p>'
    )

    return f"""
<section class="sheet">
  <span class="kicker">03 · Affected Endpoint Inventory</span>
  <h2 class="page-title">취약 엔드포인트 전체 목록 ({len(endpoints)}개)</h2>
  <p class="lede">{esc(section_id)} 항목에서 오류 정보 노출이 확인된 엔드포인트 전체입니다(샘플이 아닌 전수 목록).
  최고 심각도 → finding 건수 순으로 정렬했으며, "매칭 패턴"은 해당 엔드포인트에서 발견된 patterns 수 / 전체 patterns 수입니다.</p>
  {body}
</section>"""


# ---------------------------------------------------------------------------
# Detail (real findings, 3-step layout, real evidence screenshot)
# ---------------------------------------------------------------------------
_SK_CLASS_LABEL_KO = {"dbms": "DBMS 오류", "exception": "익셉션 오류", "http": "HTTP/서버 오류"}

_TRIGGER_FAMILY_LABEL_KO = {
    "param": "파라미터(쿼리/바디) 변조",
    "body": "요청 바디 변형",
    "path": "경로(Path) 변조",
    "method": "HTTP 메서드 변경",
    "header": "요청 헤더 변조",
}

_ENGINE_LABEL_KO = {
    "httpx": "httpx 자동 프로브",
    "zap": "OWASP ZAP 능동 스캔",
    "httpx+zap": "httpx 자동 프로브 + OWASP ZAP 능동 스캔",
}


def _g61_technique_text(group: dict[str, Any]) -> str:
    engine_label = _ENGINE_LABEL_KO.get(str(group.get("engine") or "httpx"), str(group.get("engine") or "httpx"))
    category_label = str(group.get("category_label") or "")
    rule_label = str(group.get("rule_label") or "")
    families = list(group.get("trigger_families") or [])
    if families:
        family_desc = " · ".join(
            f"{_TRIGGER_FAMILY_LABEL_KO.get(str(t.get('family')), str(t.get('family')))} "
            f"{int(t.get('count') or 0):,}건"
            for t in families
        )
    else:
        family_desc = "다중 트리거 조합"
    methods = list(group.get("sample_methods") or [])
    method_desc = ", ".join(methods) if methods else "-"
    return (
        f"{engine_label} 방식으로 대상 API에 비정상 입력을 주입하여 {category_label}({rule_label}) 유형의 "
        f"오류 노출 여부를 점검했습니다. 사용 메서드: {method_desc} · 유발 트리거: {family_desc}."
    )


def _g61_result_text(group: dict[str, Any]) -> str:
    sk_label = _SK_CLASS_LABEL_KO.get(str(group.get("sk_class") or ""), str(group.get("sk_label") or ""))
    rule_label = str(group.get("rule_label") or "")
    count = int(group.get("count") or 0)
    top_status = list(group.get("top_status_codes") or [])
    status_desc = f" (HTTP {', '.join(top_status)})" if top_status else ""
    return (
        f"{sk_label} 분류의 '{rule_label}' 패턴이 총 {count:,}건의 응답{status_desc}에서 발견되어 "
        f"서버 내부 정보가 클라이언트에 노출되고 있어 취약합니다."
    )


def _g61_remediation_text(group: dict[str, Any]) -> str:
    sk_label = _SK_CLASS_LABEL_KO.get(str(group.get("sk_class") or ""), str(group.get("sk_label") or ""))
    remediation = str(group.get("remediation") or "").strip()
    if not remediation:
        remediation = "오류 상세 정보를 클라이언트에 노출하지 말고, 일반화된 오류 메시지로 응답하며 상세 내역은 서버 로그에만 남기십시오."
    return f"[{_GUIDELINE_LABEL} · 6-1 오류페이지 정보 노출 진단 가이드 · {sk_label}] {remediation}"


def _g61_evidence_lookup(evidence_dir: Path) -> dict[str, dict[str, Any]]:
    """group_key -> first matching capture entry (webcapture/manifest.json)."""
    import json

    manifest_path = evidence_dir / "webcapture" / "manifest.json"
    lookup: dict[str, dict[str, Any]] = {}
    if not manifest_path.is_file():
        return lookup
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return lookup
    for capture in raw.get("captures") or []:
        group_key = str(capture.get("group_key") or "")
        if group_key and group_key not in lookup and capture.get("captured"):
            lookup[group_key] = capture
    return lookup


def _finding_card_html(group: dict[str, Any], evidence_dir: Path, image_lookup: dict[str, dict[str, Any]]) -> str:
    rule_label = str(group.get("rule_label") or "")
    count = int(group.get("count") or 0)
    confidence = _confidence_label(str(group.get("severity") or ""))
    sample_urls = list(group.get("sample_urls") or [])
    sample_methods = list(group.get("sample_methods") or [])
    method_prefix = f"{sample_methods[0].upper()} " if sample_methods else ""
    url_html = (
        f'<span class="url">{esc(method_prefix + sample_urls[0])}</span>' if sample_urls else ""
    )

    steps = f"""
<div class="step-list">
  <div class="step-item">
    <div class="step-label"><span class="num">1</span>해당 탐지 기법으로 테스트를 해보면</div>
    <div class="step-body">{esc(_g61_technique_text(group))}</div>
  </div>
  <div class="step-item">
    <div class="step-label"><span class="num">2</span>이런 결과가 나와서 취약해요</div>
    <div class="step-body">{esc(_g61_result_text(group))}{url_html}</div>
  </div>
  <div class="step-item reco">
    <div class="step-label"><span class="num">3</span>대응방안 ({esc(_GUIDELINE_LABEL)})</div>
    <div class="step-body">{esc(_g61_remediation_text(group))}</div>
  </div>
</div>"""

    image_html = ""
    capture = image_lookup.get(str(group.get("group_key") or ""))
    if capture:
        filename = str(capture.get("result_screenshot") or "")
        if filename:
            uri = image_data_uri(evidence_dir / "webcapture" / filename)
            if uri:
                verdict = "정보 노출 확인됨 (CONFIRMED)" if capture.get("confirmed") else "실제 캡처(브라우저 재현) — 자동 확정 미판정"
                image_html = (
                    f'<div class="evidence-img"><img src="{uri}" alt="evidence"/>'
                    f'<div class="cap">{esc(verdict)} · evidence/webcapture/{esc(filename)}</div></div>'
                )

    return (
        f'<div class="finding">'
        f'<div class="finding-head">{severity_badge(str(group.get("severity") or "info"))}'
        f'<span class="msg">{esc(rule_label)} — {esc(confidence)} · {count:,}건</span></div>'
        f'<div class="finding-body">'
        f'<dl class="kv-grid">'
        f"<dt>Origin</dt><dd>{esc(group.get('origin') or '-')}</dd>"
        f"<dt>SK 6-1 분류</dt><dd>{esc(_SK_CLASS_LABEL_KO.get(str(group.get('sk_class') or ''), str(group.get('sk_label') or '')))}</dd>"
        f"<dt>Engine</dt><dd>{esc(group.get('engine') or '-')}</dd>"
        f"</dl>{steps}{image_html}</div></div>"
    )


def _detail_page(*, section_id: str, groups: list[dict[str, Any]], evidence_dir: Path,
                  stats: dict[str, Any]) -> str:
    image_lookup = _g61_evidence_lookup(evidence_dir)
    cards = "".join(_finding_card_html(g, evidence_dir, image_lookup) for g in groups)
    stats_html = ""
    if stats.get("endpoints_probed") is not None or stats.get("requests_sent") is not None:
        parts = []
        if stats.get("endpoints_probed") is not None:
            parts.append(f"API <b>{esc(stats.get('endpoints_probed'))}</b>개")
        if stats.get("requests_sent") is not None:
            parts.append(f"요청 <b>{esc(stats.get('requests_sent'))}</b>")
        stats_html = f'<div class="stats-strip">{"".join(f"<span>{p}</span>" for p in parts)}</div>'

    return f"""
<section class="sheet">
  <span class="kicker">04 · 상세 진단 결과</span>
  <h2 class="page-title">{esc(section_id)} · 상세 진단 (전체 {len(groups)}개 패턴)</h2>
  {stats_html}
  <h3 class="section-title">Findings</h3>
  {cards if cards else '<p class="lede">조치 필요 항목 없음.</p>'}
</section>"""


# ---------------------------------------------------------------------------
# Evidence appendix (every captured screenshot, not just one per group)
# ---------------------------------------------------------------------------
def _evidence_appendix_page(*, section_id: str, evidence_dir: Path) -> str:
    import json

    manifest_path = evidence_dir / "webcapture" / "manifest.json"
    captures: list[dict[str, Any]] = []
    if manifest_path.is_file():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            captures = [c for c in (raw.get("captures") or []) if c.get("captured")]
        except (OSError, ValueError):
            captures = []

    thumbs = []
    for c in captures:
        filename = str(c.get("result_screenshot") or "")
        if not filename:
            continue
        uri = image_data_uri(evidence_dir / "webcapture" / filename)
        if not uri:
            continue
        confirmed = bool(c.get("confirmed"))
        verdict_cls = "ok" if confirmed else "miss"
        verdict_label = "CONFIRMED" if confirmed else str(c.get("failure_reason") or "미확정")
        thumbs.append(
            '<div class="evidence-thumb">'
            f'<div class="art"><img src="{uri}" alt="evidence"/></div>'
            '<div class="cap">'
            f'<div class="t">{esc(c.get("severity"))} · {esc(c.get("rule_label") or c.get("rule_id"))}</div>'
            f'<div class="p">{esc(c.get("method"))} {esc(c.get("url"))}</div>'
            f'<div class="v {verdict_cls}">{esc(verdict_label)}</div>'
            "</div></div>"
        )

    body = (
        f'<div class="evidence-grid">{"".join(thumbs)}</div>'
        if thumbs
        else '<p class="lede">캡처된 증거 스크린샷이 없습니다.</p>'
    )

    return f"""
<section class="sheet">
  <span class="kicker">05 · Evidence Appendix</span>
  <h2 class="page-title">증거 스크린샷 상세 ({len(thumbs)}건)</h2>
  <p class="lede">실제 헤드풀 브라우저(Playwright)로 대상 URL을 재현해 캡처한 실제 화면입니다.
  경로: <code style="font-family:{_FONT_MONO}">data/report/{esc(section_id)}/evidence/webcapture/</code></p>
  {body}
</section>"""


# ---------------------------------------------------------------------------
# Methodology & glossary
# ---------------------------------------------------------------------------
def _methodology_page() -> str:
    return f"""
<section class="sheet">
  <span class="kicker">06 · Methodology &amp; Glossary</span>
  <h2 class="page-title">진단 방법론 및 용어 정의</h2>

  <h3 class="section-title">사용 엔진</h3>
  <div class="two-col">
    <dl class="def-list">
      <dt>httpx</dt><dd>직접 HTTP 요청으로 응답/헤더/타이밍 차이를 비교하는 1차 프로브</dd>
      <dt>OWASP ZAP</dt><dd>능동·수동 스캔(스토리라인, 헤더, 알려진 취약 패턴)</dd>
    </dl>
    <dl class="def-list">
      <dt>Playwright</dt><dd>Chromium 기반 브라우저 리플레이 · 증거 스크린샷 실제 캡처</dd>
    </dl>
  </div>

  <h3 class="section-title">심각도(Severity) 정의</h3>
  <dl class="def-list">
    <dt><span class="badge sev-high">High</span></dt><dd>즉시 조치 필요 — 데이터 유출·인증 우회 등 직접적 악용 가능</dd>
    <dt><span class="badge sev-medium">Medium</span></dt><dd>조건부 악용 가능 — 추가 조건(권한, 환경) 충족 시 위험</dd>
    <dt><span class="badge sev-low">Low</span></dt><dd>제한적 영향 — 정보 노출 등 단독으로는 낮은 위험</dd>
    <dt><span class="badge sev-info">Info</span></dt><dd>참고용 신호 — 취약점은 아닌 진단 통계/실측 정보</dd>
  </dl>

  <h3 class="section-title">상태(Status) 정의</h3>
  <dl class="def-list">
    <dt><span class="badge status-fail">Fail</span></dt><dd>취약점 확인됨 — 조치 필요</dd>
    <dt><span class="badge status-warn">Warn</span></dt><dd>일부 확인/약한 신호 — 검토 권장</dd>
    <dt><span class="badge status-pass">Pass</span></dt><dd>진단 완료, 취약점 미발견</dd>
    <dt><span class="badge status-pending">Pending</span></dt><dd>수동 진단 범위 밖 — 사람 검토 필요</dd>
  </dl>

  <div class="callout">
    <b>한계 및 주의사항.</b> 본 보고서는 자동 진단 도구(ARGUS)의 실행 결과이며 오탐(false positive) 가능성이 있습니다.
    "진단자 확인 필요"로 분류된 finding은 표시된 신뢰도를 함께 참고하시고, High/Medium 등급 항목은
    증거 스크린샷(Evidence Appendix)으로 실제 응답을 재검증한 뒤 조치하는 것을 권장합니다.
  </div>
</section>"""


def _html_document(*, title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"/><title>{esc(title)}</title><style>{_PRINT_CSS}</style></head>
<body>{body_html}</body></html>"""


def _print_cover_pdf(cover_html: str) -> bytes:
    """Print the cover as its own zero-margin document so the dark background
    bleeds all the way to the paper edge — Chromium's page-margin box (where
    header/footer templates live) is always paper-white, so a full-bleed
    cover and a native running header/footer can't coexist on the same
    page.pdf() call. Merged with the content PDF in render_pdf()."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.set_content(cover_html, wait_until="load")
            pdf_bytes = page.pdf(format="A4", print_background=True, margin={"top": "0", "bottom": "0", "left": "0", "right": "0"})
        finally:
            browser.close()
    return pdf_bytes


def _print_content_pdf(html_doc: str, *, report_no: str) -> bytes:
    from playwright.sync_api import sync_playwright

    header_html = _HEADER_TEMPLATE.replace(
        '<span class="report-no"></span>', f"<span>{esc(report_no)}</span>"
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.set_content(html_doc, wait_until="load")
            pdf_bytes = page.pdf(
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template=header_html,
                footer_template=_FOOTER_TEMPLATE,
                margin={"top": "18mm", "bottom": "16mm", "left": "16mm", "right": "16mm"},
            )
        finally:
            browser.close()
    return pdf_bytes


def _merge_pdfs(*parts: bytes) -> bytes:
    import io

    from pypdf import PdfWriter

    writer = PdfWriter()
    for part in parts:
        writer.append(io.BytesIO(part))
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def render_pdf(*, ctx: DiagnosisContext | None = None) -> bytes:
    """Build the 6-1 PDF end to end and persist it to data/report/6-1/latest.pdf.

    Raises FileNotFoundError if no 6-1 report has been generated yet.
    """
    from app.config import BACKEND_ROOT
    from app.services.diagnosis_service import get_g61_report_summary
    from diagnosis.paths import section_evidence_dir, section_report_path
    from diagnosis.registry import get_module

    data_dir = ctx.data_dir if ctx is not None else BACKEND_ROOT / "data"
    report_path = section_report_path(data_dir, "6-1")
    if not report_path.is_file():
        raise FileNotFoundError("No report for module 6-1")
    evidence_dir = section_evidence_dir(data_dir, "6-1")

    mod = get_module("6-1")
    title = mod.title if mod is not None else "6-1"
    chapter = mod.chapter if mod is not None else 0

    payload = get_g61_report_summary()
    if payload is None:
        raise FileNotFoundError("No report for module 6-1")
    section_id = str(payload.get("section_id") or "6-1")
    status = str(payload.get("status") or "pending")
    checked_at = payload.get("checked_at")
    title = str(payload.get("title") or title)
    chapter = int(payload.get("chapter") or chapter)

    summary = dict(payload.get("g61_summary") or {})
    groups = list(summary.get("groups") or [])
    groups.sort(key=lambda g: (-_SEVERITY_RANK.get(str(g.get("severity", "")).lower(), 0), -int(g.get("count") or 0)))
    stats = dict(summary.get("stats") or {})
    base_urls = [str(u) for u in (stats.get("base_urls") or [])] or ["-"]
    top_severity = str(groups[0].get("severity")) if groups else "info"
    total = int(summary.get("total_issues") or 0)

    raw_config = _load_raw_config()
    app_name = _app_name(raw_config)
    generated_at = _now_iso()
    # checked_at isn't always present in older reports — fall back to the render date
    # rather than fabricate a scan date that never happened.
    report_date = str(checked_at or "")[:10].replace("-", "") or generated_at[:10].replace("-", "")
    report_no = f"ARGUS-RPT-{report_date}-{section_id}"

    cover_html = _cover_page(
        section_id=section_id, title=title, checked_at=checked_at,
        base_urls=base_urls, app_name=app_name, report_no=report_no, generated_at=generated_at,
    )
    content_pages = [
        _summary_page(section_id=section_id, summary=summary, stats=stats, checked_at=checked_at),
        _matrix_page(
            section_id=section_id, title=title, chapter=chapter,
            status=status, top_severity=top_severity, total=total,
        ),
        _endpoint_inventory_page(section_id=section_id, endpoints=list(summary.get("endpoints") or [])),
        _detail_page(section_id=section_id, groups=groups, evidence_dir=evidence_dir, stats=stats),
        _evidence_appendix_page(section_id=section_id, evidence_dir=evidence_dir),
        _methodology_page(),
    ]

    cover_doc = _html_document(title=f"ARGUS {section_id} 진단 보고서", body_html=cover_html)
    content_doc = _html_document(title=f"ARGUS {section_id} 진단 보고서", body_html="".join(content_pages))

    cover_pdf = _print_cover_pdf(cover_doc)
    content_pdf = _print_content_pdf(content_doc, report_no=report_no)
    pdf_bytes = _merge_pdfs(cover_pdf, content_pdf)
    (report_path.parent / "latest.pdf").write_bytes(pdf_bytes)
    return pdf_bytes
