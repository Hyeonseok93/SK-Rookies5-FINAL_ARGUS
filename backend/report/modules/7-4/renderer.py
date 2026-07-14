"""Render the normalized 7-4 document using the ARGUS A4 report design."""

from __future__ import annotations

from html import escape

from models import FindingReport, ReportDocument


_FIRST_SUMMARY_PAGE_ROWS = 10
_CONTINUATION_SUMMARY_PAGE_ROWS = 16


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _severity(value: str) -> str:
    normalized = value.lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info"


def _summary_chunks(findings: list[FindingReport]) -> list[list[FindingReport]]:
    """Split summary rows while reserving more room on the first summary page."""
    first = findings[:_FIRST_SUMMARY_PAGE_ROWS]
    remaining = findings[_FIRST_SUMMARY_PAGE_ROWS:]
    chunks = [first]
    chunks.extend(
        remaining[index:index + _CONTINUATION_SUMMARY_PAGE_ROWS]
        for index in range(0, len(remaining), _CONTINUATION_SUMMARY_PAGE_ROWS)
    )
    return chunks


def _summary_table(findings: list[FindingReport]) -> str:
    rows = "".join(
        f'''<tr><td class="mono">{_e(item.case_id)}</td><td>{_e(item.finding_type)}</td>
        <td><span class="badge sev-{_severity(item.severity)}">{_e(item.severity)}</span></td>
        <td class="url-cell">{_e(item.target)}</td></tr>'''
        for item in findings
    ) or '<tr><td colspan="4" class="empty">보고서에 포함할 증거 연결 finding이 없습니다.</td></tr>'
    return (
        '<table><thead><tr><th>Case ID</th><th>유형</th><th>심각도</th><th>대상</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )


def _summary_pages(
    report: ReportDocument,
    chunks: list[list[FindingReport]],
    total_pages: int,
    *,
    high: int,
    medium: int,
    sca: int,
) -> str:
    warning_html = "".join(f"<li>{_e(row)}</li>" for row in report.warnings)
    pages: list[str] = []
    for index, chunk in enumerate(chunks):
        page_no = index + 2
        table = _summary_table(chunk)
        if index == 0:
            body = f'''<span class="kicker">Executive Summary</span><h2>7-4 진단 결과 요약</h2>
            <p class="lede">진단 finding과 성공한 증거 스크린샷을 case ID로 연결해 최종 보고서 항목을 구성했습니다.</p>
            <div class="notice"><b>deps 파일 필수 안내</b>{_e(report.dependency_file_required)}</div>
            <div class="stats"><div class="stat"><b>{len(report.findings)}</b><span>보고서 finding</span></div><div class="stat"><b>{high}</b><span>High 이상</span></div><div class="stat"><b>{medium}</b><span>Medium</span></div><div class="stat"><b>{sca}</b><span>SCA</span></div></div>
            {table}{f'<ul class="warnings">{warning_html}</ul>' if warning_html else ''}'''
            page_class = "page summary-page"
        else:
            body = f'''<span class="kicker">Executive Summary · Continued</span>
            <h2>7-4 진단 결과 요약 - 계속</h2>
            <p class="lede summary-note">이전 페이지에서 이어지는 취약점 목록입니다.</p>{table}'''
            page_class = "page summary-page summary-continuation"
        pages.append(
            f'''<section class="{page_class}"><header class="page-header"><span>ARGUS · 7-4 진단 요약</span><span>{_e(report.report_id)}</span></header>
            <main class="page-body">{body}</main>
            <footer class="page-footer"><span>{_e(report.report_id)} · Confidential</span><span>{page_no} / {total_pages}</span></footer></section>'''
        )
    return "".join(pages)


def _finding_pages(finding: FindingReport, report: ReportDocument, page_no: int, total: int) -> str:
    images = "".join(
        f'''<figure class="evidence"><img src="{image.data_uri}" alt="{_e(image.caption)}">
        <figcaption>{_e(image.caption)}</figcaption></figure>'''
        for image in finding.images
    ) or '<div class="empty-evidence">증거 스크린샷을 생성하지 못했습니다.</div>'
    facts = "".join(f"<dt>{_e(name)}</dt><dd>{_e(value)}</dd>" for name, value in finding.facts)
    remediation = "".join(f"<li>{_e(row)}</li>" for row in finding.remediation)
    severity = _severity(finding.severity)
    return f'''
    <section class="page finding-page evidence-page">
      <header class="page-header"><span>ARGUS · 웹/API 개발보안 진단 보고서</span><span>{_e(report.report_id)}</span></header>
      <main class="page-body">
        <span class="kicker">7-4 · 상세 진단 결과 · {_e(finding.case_type.upper())}</span>
        <div class="title-row"><h2>{_e(finding.title)}</h2><span class="badge sev-{severity}">{_e(severity)}</span></div>

        <section class="report-block">
          <h3><b>01</b> 탐지 기법 및 테스트 방법</h3>
          <p>{_e(finding.test_method)}</p>
          <div class="evidence-grid">{images}</div>
        </section>
      </main>
      <footer class="page-footer"><span>{_e(report.report_id)} · Confidential</span><span>{page_no} / {total}</span></footer>
    </section>

    <section class="page finding-page result-page">
      <header class="page-header"><span>ARGUS · 웹/API 개발보안 진단 보고서</span><span>{_e(report.report_id)}</span></header>
      <main class="page-body">
        <span class="kicker">7-4 · 취약 판정 및 대응방안 · {_e(finding.case_type.upper())}</span>
        <div class="title-row"><h2>{_e(finding.title)}</h2><span class="badge sev-{severity}">{_e(severity)}</span></div>
        <section class="report-block assessment">
          <h3><b>02</b> 진단 결과 및 취약 판정 근거</h3>
          <dl class="kv-grid">{facts}</dl>
          <p class="decision">{_e(finding.assessment)}</p>
        </section>

        <section class="report-block remediation">
          <h3><b>03</b> 대응방안</h3>
          <ol>{remediation}</ol>
          <p class="reference">{_e(finding.guideline_reference)}</p>
        </section>
      </main>
      <footer class="page-footer"><span>{_e(report.report_id)} · Confidential</span><span>{page_no + 1} / {total}</span></footer>
    </section>'''


def render_html(report: ReportDocument) -> str:
    summary_chunks = _summary_chunks(report.findings)
    summary_page_count = len(summary_chunks)
    total_pages = 1 + summary_page_count + (len(report.findings) * 2)
    high = sum(1 for row in report.findings if row.severity.lower() in {"critical", "high"})
    medium = sum(1 for row in report.findings if row.severity.lower() == "medium")
    sca = sum(1 for row in report.findings if row.case_type == "sca")
    summary_pages = _summary_pages(
        report,
        summary_chunks,
        total_pages,
        high=high,
        medium=medium,
        sca=sca,
    )
    detail_start_page = 2 + summary_page_count
    detail_pages = "".join(
        _finding_pages(item, report, detail_start_page + (index * 2), total_pages)
        for index, item in enumerate(report.findings)
    )
    return f'''<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>ARGUS 7-4 진단 보고서</title>
<style>
:root{{--paper:#f7f8f7;--raised:#fff;--ink:#12161f;--soft:#454e59;--muted:#6b7480;--line:#d9dfe3;--strong:#b7c0c7;--accent:#0f7a8c;--critical:#8b1010;--high:#b0261f;--medium:#a15c06;--low:#2c5f9e;--green:#1f6b45;--sans:"Pretendard Variable",Pretendard,"Noto Sans KR","Malgun Gothic",sans-serif;--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
*{{box-sizing:border-box}} body{{margin:0;background:#e9edf0;color:var(--ink);font-family:var(--sans);font-size:13px;line-height:1.6}} .report{{display:flex;flex-direction:column;gap:28px;align-items:center;padding:28px}}
.page{{width:794px;height:1123px;background:var(--paper);display:flex;flex-direction:column;overflow:hidden;box-shadow:0 18px 40px -22px #0a0e1459;page-break-after:always;break-after:page}}
.page-header,.page-footer{{display:flex;justify-content:space-between;padding:14px 30px;border-bottom:1px solid var(--line);font:9.5px var(--mono);letter-spacing:.03em;text-transform:uppercase;color:var(--muted)}} .page-footer{{margin-top:auto;border-top:1px solid var(--line);border-bottom:0;padding:10px 30px 16px}}
.page-body{{padding:28px 30px 22px}} .cover{{color:#eef3f5;background:radial-gradient(880px 460px at 82% -6%,#123443 0%,transparent 60%),linear-gradient(165deg,#0a1119,#0d1b26)}} .cover .page-header,.cover .page-footer{{border-color:#ffffff1f;color:#9fb4bd}}
.cover .page-body{{padding:84px 48px;display:flex;flex-direction:column;justify-content:space-between;flex:1}} .cover .eyebrow,.kicker{{font:700 10px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:#54c5d5}} .cover h1{{font-size:42px;line-height:1.18;margin:20px 0}} .cover .subtitle{{max-width:590px;color:#b8c8cf;font-size:15px}} .cover dl{{margin-top:80px;display:grid;grid-template-columns:130px 1fr;gap:10px;border-top:1px solid #ffffff26;padding-top:24px}} .cover dt{{color:#9fb4bd}} .cover dd{{margin:0;font-family:var(--mono)}}
h2{{font-size:25px;line-height:1.3;margin:7px 0 18px}} .lede{{color:var(--soft);max-width:650px}} .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:20px 0}} .stat{{background:var(--raised);border:1px solid var(--line);padding:15px;border-radius:4px}} .stat b{{display:block;font:700 24px var(--mono)}} .stat span{{font-size:10px;color:var(--muted)}}
.notice{{border-left:3px solid var(--accent);background:#eaf5f6;border-radius:3px;padding:11px 13px;margin:14px 0 20px;color:var(--soft);font-size:10.5px}} .notice b{{display:block;color:var(--accent);margin-bottom:3px}}
table{{width:100%;border-collapse:collapse;font-size:11px}} th{{text-align:left;color:var(--muted);border-bottom:1px solid var(--strong);padding:8px}} td{{border-bottom:1px solid var(--line);padding:9px 8px;vertical-align:top}} .mono,.reference{{font-family:var(--mono)}} .url-cell{{word-break:break-all}} .empty{{text-align:center;color:var(--muted);padding:30px}}
.summary-page .page-body{{padding-bottom:64px}} .summary-page tr{{break-inside:avoid}} .summary-continuation .page-body{{padding-top:42px}} .summary-continuation h2{{margin-bottom:8px}} .summary-note{{margin:0 0 24px}}
.badge{{display:inline-block;font:700 9px var(--mono);text-transform:uppercase;padding:2px 7px;border-radius:999px;border:1px solid currentColor}} .sev-critical{{color:var(--critical);background:#8b101014}} .sev-high{{color:var(--high);background:#b0261f14}} .sev-medium{{color:var(--medium);background:#a15c0614}} .sev-low{{color:var(--low);background:#2c5f9e14}} .sev-info{{color:var(--muted);background:#6b748014}}
.title-row{{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}} .title-row h2{{font-size:18px;max-width:650px}} .report-block{{border:1px solid var(--line);border-radius:4px;background:var(--raised);padding:14px 15px;margin:0 0 13px;break-inside:avoid}} .report-block h3{{font-size:13px;margin:0 0 8px}} .report-block h3 b{{font:700 10px var(--mono);color:var(--accent);margin-right:8px}} .report-block p{{font-size:11px;color:var(--soft);margin:7px 0}}
.evidence-grid{{display:grid;grid-template-columns:1fr;gap:12px;margin-top:12px}} figure.evidence{{margin:0;border:1px solid #2b2f34;border-top:3px solid #e7782f;border-radius:4px;overflow:hidden;background:#111315}} figure.evidence img{{width:100%;height:300px;display:block;object-fit:contain;background:#171a1e}} figure.evidence figcaption{{padding:7px 9px;color:#d8dde2;font:9px var(--mono)}} .empty-evidence{{border:1px dashed var(--strong);padding:24px;text-align:center;color:var(--muted)}}
.kv-grid{{display:grid;grid-template-columns:105px 1fr;gap:4px 10px;font-size:10.5px;margin:0}} .kv-grid dt{{color:var(--muted)}} .kv-grid dd{{margin:0;font-family:var(--mono);word-break:break-all;color:var(--soft)}} .decision{{padding-top:9px;border-top:1px dashed var(--line)}} .remediation{{border-left:3px solid var(--green)}} .remediation h3,.remediation h3 b{{color:var(--green)}} .remediation ol{{font-size:11px;color:var(--soft);padding-left:20px;margin:7px 0}} .remediation li+li{{margin-top:5px}} .reference{{font-size:9px!important;color:var(--muted)!important;border-top:1px dashed var(--line);padding-top:7px}}
.warnings{{font-size:10px;color:var(--medium)}}
@page{{size:A4;margin:0}} @media print{{body{{background:#fff}}.report{{display:block;padding:0}}.page{{box-shadow:none;margin:0;width:210mm;height:297mm;overflow:hidden;break-inside:avoid}}}}
</style></head><body><div class="report">
<section class="page cover"><header class="page-header"><span>ARGUS</span><span>{_e(report.report_id)}</span></header><main class="page-body"><div><div class="eyebrow">Security Assessment Report · 7-4</div><h1>취약한 보안설정<br>진단 보고서</h1><p class="subtitle">ARGUS 자동 진단 결과와 웹 보안설정·오픈소스 의존성 증거 스크린샷을 웹/API 개발보안 기준으로 정리한 보고서입니다.</p></div><dl><dt>진단 항목</dt><dd>7-4 · {_e(report.title)}</dd><dt>진단 일시</dt><dd>{_e(report.checked_at or '-')}</dd><dt>보고서 생성</dt><dd>{_e(report.generated_at)}</dd><dt>진단 상태</dt><dd>{_e(report.status)}</dd></dl></main><footer class="page-footer"><span>Confidential</span><span>1 / {total_pages}</span></footer></section>
{summary_pages}
{detail_pages}</div></body></html>'''
