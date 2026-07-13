"""Render a single diagnosis section's report + evidence as a downloadable PDF.

Two section-specific renderers exist because the underlying report shapes are
very different:

- 1-5 stores a normal (small) findings list straight from ``latest.yaml``.
- 6-1 stores tens of thousands of raw findings — it must go through the
  aggregated group summary (``report_summary.py``) that the dashboard already
  uses, never the raw YAML, or rendering would try to loop over ~74k rows.

Everything else falls back to a generic renderer that dumps whatever
evidence fields a finding has, so the shared endpoint degrades gracefully
for sections outside this scope instead of erroring.
"""

from __future__ import annotations

import base64
import html
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.config import BACKEND_ROOT
from diagnosis.context import DiagnosisContext
from diagnosis.paths import section_evidence_dir, section_report_path
from diagnosis.result import SectionReport

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_LABEL_KO = {"high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}

_FONT_SANS = (
    '"Pretendard Variable", Pretendard, "Noto Sans KR", -apple-system, '
    '"Segoe UI", "Malgun Gothic", "Apple SD Gothic Neo", sans-serif'
)
_FONT_MONO = '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _image_data_uri(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return f"data:image/png;base64,{base64.b64encode(raw).decode('ascii')}"


def _status_badge(status: str) -> str:
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
        "pass": "ok",
        "fail": "bad",
        "warn": "warn",
        "warning": "warn",
        "error": "bad",
    }.get(status, "neutral")
    return f'<span class="badge status-{cls}">{_esc(label)}</span>'


def _severity_badge(sev: str) -> str:
    sev = (sev or "info").lower()
    return f'<span class="badge sev-{sev}">{_esc(sev.upper())}</span>'


_BASE_CSS = f"""
* {{ box-sizing: border-box; }}
body {{
  margin: 0; font-family: {_FONT_SANS}; color: #12161f; font-size: 12.5px; line-height: 1.6;
}}
.report h1 {{ font-size: 21px; font-weight: 800; margin: 0 0 4px; letter-spacing: -0.005em; }}
.report .meta-line {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 4px; }}
.report .meta-line .ts {{ font-family: {_FONT_MONO}; font-size: 10px; color: #6b7480; }}
.report p.message {{ color: #454e59; margin: 6px 0 18px; }}

.badge {{
  display: inline-block; font-family: {_FONT_MONO}; font-size: 9px; font-weight: 700;
  letter-spacing: 0.04em; text-transform: uppercase; padding: 2px 7px; border-radius: 999px;
  border: 1px solid currentColor; white-space: nowrap;
}}
.badge.status-ok {{ color: #1f6b45; background: #1f6b4514; }}
.badge.status-bad {{ color: #b0261f; background: #b0261f14; }}
.badge.status-warn {{ color: #a15c06; background: #a15c0614; }}
.badge.status-neutral {{ color: #6b7480; background: #6b748014; }}
.badge.sev-high {{ color: #b0261f; background: #b0261f14; }}
.badge.sev-medium {{ color: #a15c06; background: #a15c0614; }}
.badge.sev-low {{ color: #2c5f9e; background: #2c5f9e14; }}
.badge.sev-info {{ color: #6b7480; background: #6b748014; }}

.stats-strip {{
  display: flex; flex-wrap: wrap; gap: 6px 16px; padding: 9px 12px; margin-bottom: 18px;
  background: #f7f8f7; border: 1px solid #d9dfe3; border-radius: 4px;
  font-family: {_FONT_MONO}; font-size: 10.5px; color: #454e59;
}}
.stats-strip b {{ color: #12161f; }}

h2.section-title {{
  font-size: 13.5px; font-weight: 700; margin: 24px 0 10px; padding-bottom: 6px;
  border-bottom: 1px solid #d9dfe3; break-after: avoid;
}}
h2.section-title:first-of-type {{ margin-top: 0; }}

.finding, .group-card {{
  border: 1px solid #d9dfe3; border-radius: 4px; margin-bottom: 10px; overflow: hidden;
  break-inside: avoid;
}}
.finding-head, .group-head {{
  display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  background: #f7f8f7; border-bottom: 1px solid #d9dfe3; flex-wrap: wrap;
}}
.finding-head .msg, .group-head .msg {{ font-size: 11.5px; font-weight: 600; color: #12161f; }}
.finding-body, .group-body {{ padding: 10px 12px; }}
.kv-grid {{ display: grid; grid-template-columns: 118px 1fr; gap: 4px 10px; font-size: 10.5px; }}
.kv-grid dt {{ color: #6b7480; margin: 0; }}
.kv-grid dd {{ margin: 0; font-family: {_FONT_MONO}; color: #454e59; word-break: break-all; }}
.note {{ margin-top: 9px; padding-top: 9px; border-top: 1px dashed #d9dfe3; font-size: 10.5px; color: #454e59; }}
.note b {{ color: #12161f; }}
.note.reco {{ color: #1f6b45; }}
.note.reco b {{ color: #1f6b45; }}
.tag {{ font-family: {_FONT_MONO}; font-size: 9.5px; color: #6b7480; }}

.evidence-img {{ margin-top: 10px; }}
.evidence-img img {{
  max-width: 100%; border: 1px solid #d9dfe3; border-radius: 3px; display: block;
}}
.evidence-img .cap {{ margin-top: 4px; font-family: {_FONT_MONO}; font-size: 9px; color: #6b7480; }}
.evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 10px; }}

.samples {{ margin-top: 8px; padding: 8px 10px; background: #f7f8f7; border: 1px solid #d9dfe3; border-radius: 3px; }}
.samples .label {{ font-size: 9.5px; color: #6b7480; margin-bottom: 4px; }}
.samples ul {{ margin: 0; padding-left: 16px; font-family: {_FONT_MONO}; font-size: 10px; color: #2c5f9e; }}
.samples li {{ word-break: break-all; margin-bottom: 2px; }}
.snippet {{ font-family: {_FONT_MONO}; font-size: 9.5px; color: #454e59; white-space: pre-wrap; word-break: break-all; }}

.callout {{
  margin-top: 6px; padding: 10px 12px; border: 1px solid #d9dfe3; border-left: 3px solid #0f7a8c;
  border-radius: 3px; background: #0f7a8c14; font-size: 10.5px; color: #454e59;
}}
.empty {{ color: #1f6b45; font-size: 11.5px; padding: 10px 0; }}
"""

_HEADER_TEMPLATE = """
<div style="width:100%; font-size:8px; font-family:ui-monospace,Menlo,monospace;
  color:#6b7480; padding:0 16mm; display:flex; justify-content:space-between;">
  <span>ARGUS · 웹/API 개발보안 진단 보고서</span>
  <span class="section-id-slot"></span>
</div>
"""

_FOOTER_TEMPLATE = """
<div style="width:100%; font-size:8px; font-family:ui-monospace,Menlo,monospace;
  color:#6b7480; padding:0 16mm; display:flex; justify-content:space-between;">
  <span>Confidential · ARGUS Diagnosis Engine</span>
  <span><span class="pageNumber"></span> / <span class="totalPages"></span></span>
</div>
"""


def _header_template(section_id: str) -> str:
    return _HEADER_TEMPLATE.replace(
        '<span class="section-id-slot"></span>',
        f"<span>{_esc(section_id)}</span>",
    )


# ---------------------------------------------------------------------------
# 1-5 — plain findings list straight from latest.yaml
# ---------------------------------------------------------------------------

_G15_KNOWN_FIELDS = [
    ("engine", "Engine"),
    ("trigger", "Trigger"),
    ("trigger_label", "ZAP Rule"),
    ("risk", "ZAP Risk"),
    ("plugin_id", "ZAP Plugin ID"),
    ("baseline_location", "Baseline Location"),
    ("location", "Location / Marker"),
    ("confirmed_redirect", "Confirmed redirect"),
    ("stored", "Stored (persisted reflect)"),
    ("content_type", "Content-Type"),
    ("acao", "Access-Control-Allow-Origin"),
    ("acac", "Access-Control-Allow-Credentials"),
    ("probe_origin", "Probe Origin"),
    ("reason", "Reason"),
    ("domain", "Domain"),
]


def _g15_status_line(evidence: dict[str, Any]) -> str:
    if evidence.get("baseline_status") is not None or evidence.get("test_status") is not None:
        return f"HTTP {evidence.get('baseline_status', '-')} → {evidence.get('test_status', '-')}"
    if evidence.get("http_status") is not None:
        return f"HTTP {evidence.get('http_status')}"
    return ""


def _g15_target_url(evidence: dict[str, Any]) -> str:
    for key in ("test_url", "url", "base_url", "baseline_url", "label"):
        raw = str(evidence.get(key) or "").split("#", 1)[0]
        if not raw:
            continue
        parsed = urlsplit(raw)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return raw
    return ""


def _g15_case_id(evidence: dict[str, Any]) -> str:
    """Mirrors screenshot/modules/1-5/selector.py's dedupe key + stable_finding_id
    (duplicated on purpose — importing that sibling package would collide bare
    module names like ``selector``/``models`` across other capture modules
    loaded in the same long-lived process)."""
    rule_id = str(evidence.get("rule_id") or "")
    raw_url = _g15_target_url(evidence)
    path = urlsplit(raw_url).path.rstrip("/") or "/"
    param = str(evidence.get("param_name") or evidence.get("param") or "").lower()
    key = "|".join((rule_id, path, param))
    return f"1-5-{sha256(key.encode('utf-8')).hexdigest()[:10]}"


def _g15_stats_html(stats: dict[str, Any]) -> str:
    redirect = dict(stats.get("redirect") or {})
    reflected_probe = dict(stats.get("reflected_probe") or {})
    reflected_xss = dict(stats.get("reflected_xss") or {})
    cors = dict(stats.get("cors") or {})
    parts = [
        f"probe_mode <b>{_esc(stats.get('probe_mode', '-'))}</b>",
        (
            f"redirect probed <b>{_esc(redirect.get('probed', '-'))}</b> · "
            f"errors <b>{_esc(redirect.get('errors', '-'))}</b> · "
            f"open_redirects <b>{_esc(redirect.get('open_redirects', '-'))}</b>"
        ),
        (
            f"reflected_probe <b>{_esc(reflected_probe.get('probed', '-'))}</b> "
            f"(confirmed {_esc(reflected_probe.get('confirmed', '-'))})"
        ),
        (
            f"reflected_xss <b>{_esc(reflected_xss.get('probed', '-'))}</b> "
            f"(candidate {_esc(reflected_xss.get('candidate', '-'))})"
        ),
        f"cors probed <b>{_esc(cors.get('probed', '-'))}</b> · issues <b>{_esc(cors.get('issues', '-'))}</b>",
    ]
    return f'<div class="stats-strip">{"".join(f"<span>{p}</span>" for p in parts)}</div>'


def _g15_evidence_lookup(evidence_dir: Path) -> dict[str, Path]:
    lookup: dict[str, Path] = {}
    if not evidence_dir.is_dir():
        return lookup
    for case_dir in evidence_dir.glob("1-5-*"):
        if not case_dir.is_dir():
            continue
        combined = case_dir / "03_combined.png"
        if combined.is_file():
            lookup[case_dir.name] = combined
    return lookup


def _render_g15(report: SectionReport, evidence_dir: Path) -> str:
    findings = [f for f in report.findings if f.message != "1-5 scan statistics"]
    stats_finding = next((f for f in report.findings if f.message == "1-5 scan statistics"), None)
    image_lookup = _g15_evidence_lookup(evidence_dir)

    parts: list[str] = []
    if stats_finding is not None:
        stats = dict((stats_finding.evidence or {}).get("stats") or {})
        if stats:
            parts.append(_g15_stats_html(stats))

    parts.append(f'<h2 class="section-title">Findings ({len(findings)})</h2>')
    if not findings:
        parts.append('<p class="empty">발견된 finding이 없습니다.</p>')

    ordered = sorted(findings, key=lambda f: -_SEVERITY_RANK.get(f.severity.lower(), 0))
    for finding in ordered:
        evidence = dict(finding.evidence or {})
        rows = []
        for key, label in _G15_KNOWN_FIELDS:
            value = evidence.get(key)
            if value not in (None, ""):
                rows.append(f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>")
        for key, label in (
            ("url", "URL"),
            ("method", "Method"),
            ("param_name", "Param"),
            ("param", "Param"),
            ("payload_used", "Payload"),
            ("payload", "Payload"),
        ):
            value = evidence.get(key)
            if value not in (None, ""):
                rows.append(f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>")
        status_line = _g15_status_line(evidence)
        if status_line:
            rows.append(f"<dt>Status</dt><dd>{_esc(status_line)}</dd>")

        note_html = ""
        description = str(evidence.get("description") or "")
        if description:
            note_html += f'<div class="note"><b>설명.</b> {_esc(description)}</div>'
        recommendation = str(evidence.get("recommendation") or "")
        if recommendation:
            note_html += f'<div class="note reco"><b>대응방안.</b> {_esc(recommendation)}</div>'

        image_html = ""
        case_id = _g15_case_id(evidence)
        image_path = image_lookup.get(case_id)
        if image_path is not None:
            uri = _image_data_uri(image_path)
            if uri:
                image_html = (
                    f'<div class="evidence-img"><img src="{uri}" alt="evidence"/>'
                    f'<div class="cap">evidence/{_esc(case_id)}/03_combined.png</div></div>'
                )

        parts.append(
            f'<div class="finding">'
            f'<div class="finding-head">{_severity_badge(finding.severity)}'
            f'<span class="msg">{_esc(finding.message)}</span></div>'
            f'<div class="finding-body"><dl class="kv-grid">{"".join(rows)}</dl>'
            f"{note_html}{image_html}</div></div>"
        )

    return "".join(parts)


# ---------------------------------------------------------------------------
# 6-1 — aggregated group summary only (report has 10k+ raw findings)
# ---------------------------------------------------------------------------

_SK_CLASS_LABEL_KO = {"dbms": "DBMS 오류", "exception": "익셉션 오류", "http": "HTTP/서버 오류"}


def _g61_stats_html(stats: dict[str, Any]) -> str:
    if not stats:
        return ""
    parts = []
    if stats.get("endpoints_probed") is not None:
        parts.append(f"API <b>{_esc(stats.get('endpoints_probed'))}</b>개")
    if stats.get("requests_sent") is not None:
        parts.append(f"요청 <b>{_esc(stats.get('requests_sent'))}</b>")
    if not parts:
        return ""
    return f'<div class="stats-strip">{"".join(f"<span>{p}</span>" for p in parts)}</div>'


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


def _render_g61(summary: dict[str, Any], status: str, evidence_dir: Path) -> str:
    stats = dict(summary.get("stats") or {})
    groups = list(summary.get("groups") or [])
    groups.sort(key=lambda g: (-_SEVERITY_RANK.get(str(g.get("severity", "")).lower(), 0), -int(g.get("count") or 0)))
    image_lookup = _g61_evidence_lookup(evidence_dir)

    parts: list[str] = []
    by_sk = dict(summary.get("by_sk") or {})
    total = int(summary.get("total_issues") or 0)
    overview = (
        f"총 <b>{total:,}</b>건 · DBMS {by_sk.get('dbms', 0):,} · "
        f"익셉션 {by_sk.get('exception', 0):,} · HTTP/서버 {by_sk.get('http', 0):,}"
    )
    parts.append(f'<div class="callout">{overview}</div>')

    stats_html = _g61_stats_html(stats)
    if stats_html:
        parts.append(stats_html)

    parts.append(f'<h2 class="section-title">이슈 그룹 ({len(groups)}개)</h2>')
    if not groups:
        parts.append('<p class="empty">조치 필요 항목 없음.</p>')

    for group in groups:
        origin = str(group.get("origin") or "-")
        sk_label = _SK_CLASS_LABEL_KO.get(str(group.get("sk_class") or ""), str(group.get("sk_label") or ""))
        rule_label = str(group.get("rule_label") or "")
        category_label = str(group.get("category_label") or "")
        engine = str(group.get("engine") or "")
        count = int(group.get("count") or 0)
        remediation = str(group.get("remediation") or "")
        sample_urls = list(group.get("sample_urls") or [])[:5]
        sample_methods = list(group.get("sample_methods") or [])
        sample_snippets = list(group.get("sample_snippets") or [])[:2]
        top_status = list(group.get("top_status_codes") or [])

        rows = [
            f"<dt>SK 6-1 분류</dt><dd>{_esc(sk_label)}</dd>",
            f"<dt>세부</dt><dd>{_esc(category_label)}</dd>",
            f"<dt>Origin</dt><dd>{_esc(origin)}</dd>",
            f"<dt>Engine</dt><dd>{_esc(engine)}</dd>",
            f"<dt>건수</dt><dd>{count:,}</dd>",
        ]
        if top_status:
            rows.append(f"<dt>HTTP status</dt><dd>{_esc(', '.join(top_status))}</dd>")

        samples_html = ""
        if sample_urls:
            method_prefix = f"{sample_methods[0].upper()} " if sample_methods else ""
            items = "".join(f"<li>{method_prefix}{_esc(urlsplit(u).path or u)}</li>" for u in sample_urls)
            samples_html += f'<div class="samples"><div class="label">샘플 URL ({len(sample_urls)})</div><ul>{items}</ul></div>'
        if sample_snippets:
            snippet_text = "\n\n".join(sample_snippets)
            samples_html += f'<div class="samples"><div class="label">응답 snippet</div><div class="snippet">{_esc(snippet_text)}</div></div>'

        note_html = f'<div class="note reco"><b>조치.</b> {_esc(remediation)}</div>' if remediation else ""

        image_html = ""
        capture = image_lookup.get(str(group.get("group_key") or ""))
        if capture:
            filename = str(capture.get("result_screenshot") or "")
            if filename:
                uri = _image_data_uri(evidence_dir / "webcapture" / filename)
                if uri:
                    image_html = (
                        f'<div class="evidence-img"><img src="{uri}" alt="evidence"/>'
                        f'<div class="cap">evidence/webcapture/{_esc(filename)}</div></div>'
                    )

        parts.append(
            f'<div class="group-card">'
            f'<div class="group-head">{_severity_badge(str(group.get("severity") or "info"))}'
            f'<span class="msg">{_esc(rule_label)}</span></div>'
            f'<div class="group-body"><dl class="kv-grid">{"".join(rows)}</dl>'
            f"{samples_html}{note_html}{image_html}</div></div>"
        )

    return "".join(parts)


# ---------------------------------------------------------------------------
# generic fallback for any other section
# ---------------------------------------------------------------------------

_GENERIC_SKIP_KEYS = {"stats"}


def _render_generic(report: SectionReport) -> str:
    findings = [f for f in report.findings if not str(f.message).endswith("scan statistics")]
    ordered = sorted(findings, key=lambda f: -_SEVERITY_RANK.get(f.severity.lower(), 0))

    parts = [f'<h2 class="section-title">Findings ({len(ordered)})</h2>']
    if not ordered:
        parts.append('<p class="empty">발견된 finding이 없습니다.</p>')

    for finding in ordered:
        evidence = {k: v for k, v in (finding.evidence or {}).items() if k not in _GENERIC_SKIP_KEYS}
        rows = []
        for key, value in evidence.items():
            if value in (None, "", [], {}):
                continue
            rows.append(f"<dt>{_esc(key)}</dt><dd>{_esc(str(value)[:400])}</dd>")
        parts.append(
            f'<div class="finding">'
            f'<div class="finding-head">{_severity_badge(finding.severity)}'
            f'<span class="msg">{_esc(finding.message)}</span></div>'
            f'<div class="finding-body"><dl class="kv-grid">{"".join(rows)}</dl></div></div>'
        )
    return "".join(parts)


# ---------------------------------------------------------------------------
# assembly + PDF rendering
# ---------------------------------------------------------------------------


def _html_document(*, section_id: str, title: str, chapter: int, status: str, message: str,
                    checked_at: str | None, body_html: str) -> str:
    checked = _esc(checked_at) if checked_at else "-"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"/><style>{_BASE_CSS}</style></head>
<body>
<div class="report">
  <h1>{_esc(section_id)} · {_esc(title)}</h1>
  <div class="meta-line">
    {_status_badge(status)}
    <span class="tag">Chapter {chapter}</span>
    <span class="ts">checked_at {checked}</span>
  </div>
  {f'<p class="message">{_esc(message)}</p>' if message else ""}
  {body_html}
</div>
</body></html>"""


def render_report_pdf(section_id: str, *, ctx: DiagnosisContext | None = None) -> bytes:
    """Build a single-section PDF from latest.yaml + evidence/. Raises
    FileNotFoundError if no report has been generated for this section yet."""
    from diagnosis.registry import get_module

    data_dir = ctx.data_dir if ctx is not None else BACKEND_ROOT / "data"
    report_path = section_report_path(data_dir, section_id)
    if not report_path.is_file():
        raise FileNotFoundError(f"No report for module {section_id}")
    evidence_dir = section_evidence_dir(data_dir, section_id)

    mod = get_module(section_id)
    title = mod.title if mod is not None else section_id
    chapter = mod.chapter if mod is not None else 0

    if section_id == "6-1":
        from app.services.diagnosis_service import get_g61_report_summary

        payload = get_g61_report_summary()
        if payload is None:
            raise FileNotFoundError(f"No report for module {section_id}")
        status = str(payload.get("status") or "pending")
        message = str(payload.get("message") or "")
        checked_at = payload.get("checked_at")
        title = str(payload.get("title") or title)
        chapter = int(payload.get("chapter") or chapter)
        body_html = _render_g61(dict(payload.get("g61_summary") or {}), status, evidence_dir)
    else:
        import yaml

        raw = yaml.safe_load(report_path.read_text(encoding="utf-8")) or {}
        report = SectionReport.from_dict(raw)
        status = report.status
        message = report.message
        checked_at = report.checked_at
        title = report.title or title
        chapter = report.chapter or chapter
        if section_id == "1-5":
            body_html = _render_g15(report, evidence_dir)
        else:
            body_html = _render_generic(report)

    html_doc = _html_document(
        section_id=section_id,
        title=title,
        chapter=chapter,
        status=status,
        message=message,
        checked_at=checked_at,
        body_html=body_html,
    )

    return _print_pdf(html_doc, section_id=section_id)


def _print_pdf(html_doc: str, *, section_id: str) -> bytes:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.set_content(html_doc, wait_until="load")
            pdf_bytes = page.pdf(
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template=_header_template(section_id),
                footer_template=_FOOTER_TEMPLATE,
                margin={"top": "18mm", "bottom": "16mm", "left": "16mm", "right": "16mm"},
            )
        finally:
            browser.close()
    return pdf_bytes


def report_pdf_filename(section_id: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"argus-{section_id}-report-{stamp}.pdf"
