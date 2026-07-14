"""Burp-like evidence overlay for 1-5 (unvalidated redirect/forward) findings."""

from __future__ import annotations

import html

from models import RedirectCase


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


_BASE_CSS = """
#g15-root, #g15-root * { box-sizing: border-box !important; }
#g15-root { position: fixed !important; inset: 0 !important; z-index: 2147483647 !important;
  pointer-events: none !important; font-family: Arial, "Noto Sans KR", sans-serif !important; }
#g15-panel { position: absolute !important; left: 0 !important; width: 100vw !important;
  background: #111315 !important; color: #e4e8ec !important; border-top: 4px solid #e7782f !important; }
#g15-tabs { height: 34px !important; padding: 8px 12px !important; background: #25282c !important;
  color: #aaa !important; font-size: 12px !important; font-weight: 700 !important; }
#g15-tabs b { color: #ef873e !important; margin-right: 22px !important; }
#g15-target { height: 34px !important; padding: 8px 12px !important; background: #191b1e !important;
  border-block: 1px solid #393d42 !important; font: 12px ui-monospace, monospace !important;
  white-space: nowrap !important; overflow: hidden !important; text-overflow: ellipsis !important; }
#g15-columns { display: grid !important; grid-template-columns: 1fr 1fr !important; }
.g15-col { min-width: 0 !important; border-right: 1px solid #383c41 !important; }
.g15-head { height: 32px !important; padding: 8px 11px !important; background: #25282c !important;
  color: #72d68b !important; font-size: 12px !important; font-weight: 700 !important; }
.g15-pre { margin: 0 !important; padding: 12px !important; overflow: hidden !important;
  color: #d8dde2 !important; white-space: pre-wrap !important; overflow-wrap: anywhere !important;
  font: 11px/1.48 ui-monospace, SFMono-Regular, Menlo, monospace !important; }
"""


def _summary_text(case: RedirectCase) -> str:
    lines = [
        f"Rule: {case.rule_id}",
        f"Severity: {case.severity.upper()}",
        f"Method: {case.method}",
        f"Parameter: {case.param_name or '-'}",
        f"Payload: {case.payload or '-'}",
        case.status_line,
        "",
        *case.detail_lines,
    ]
    return "\n".join(line for line in lines if line is not None)


def _finding_text(case: RedirectCase) -> str:
    lines = [case.title, "", "Description:", case.description or "-", ""]
    if case.recommendation:
        lines.extend(["Recommendation:", case.recommendation])
    return "\n".join(lines)


def evidence_overlay(case: RedirectCase, *, full: bool) -> tuple[str, str]:
    top = "0" if full else "260px"
    height = "100vh" if full else "calc(100vh - 260px)"
    css = _BASE_CSS + f"""
#g15-panel {{ top: {top} !important; height: {height} !important; }}
#g15-columns {{ height: calc({height} - 68px) !important; }}
.g15-pre {{ height: calc({height} - 100px) !important; }}
"""
    markup = f"""
<div id="g15-panel">
  <div id="g15-tabs"><b>Burp Suite Professional</b> Target &nbsp; Proxy &nbsp; Repeater</div>
  <div id="g15-target">Target: {_esc(case.display_url)}</div>
  <div id="g15-columns">
    <div class="g15-col"><div class="g15-head">Request / Probe Summary</div>
      <pre class="g15-pre">{_esc(_summary_text(case))}</pre></div>
    <div class="g15-col"><div class="g15-head">Finding Details</div>
      <pre class="g15-pre">{_esc(_finding_text(case))}</pre></div>
  </div>
</div>"""
    return css, markup
