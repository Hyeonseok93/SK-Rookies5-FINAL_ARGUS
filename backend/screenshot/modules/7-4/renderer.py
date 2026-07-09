"""Burp-like evidence overlays for 7-4."""

from __future__ import annotations

import html

from models import ScaCase, WebConfigCase


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


_BASE_CSS = """
#g74-root, #g74-root * { box-sizing: border-box !important; }
#g74-root { position: fixed !important; inset: 0 !important; z-index: 2147483647 !important;
  pointer-events: none !important; font-family: Arial, "Noto Sans KR", sans-serif !important; }
#g74-panel { position: absolute !important; left: 0 !important; width: 100vw !important;
  background: #111315 !important; color: #e4e8ec !important; border-top: 4px solid #e7782f !important; }
#g74-tabs { height: 34px !important; padding: 8px 12px !important; background: #25282c !important;
  color: #aaa !important; font-size: 12px !important; font-weight: 700 !important; }
#g74-tabs b { color: #ef873e !important; margin-right: 22px !important; }
#g74-target { height: 34px !important; padding: 8px 12px !important; background: #191b1e !important;
  border-block: 1px solid #393d42 !important; font: 12px ui-monospace, monospace !important; }
#g74-columns { display: grid !important; grid-template-columns: 1fr 1fr !important; }
.g74-col { min-width: 0 !important; border-right: 1px solid #383c41 !important; }
.g74-head { height: 32px !important; padding: 8px 11px !important; background: #25282c !important;
  color: #72d68b !important; font-size: 12px !important; font-weight: 700 !important; }
.g74-pre { margin: 0 !important; padding: 12px !important; overflow: hidden !important;
  color: #d8dde2 !important; white-space: pre-wrap !important; overflow-wrap: anywhere !important;
  font: 11px/1.48 ui-monospace, SFMono-Regular, Menlo, monospace !important; }
"""


def _header_text(case: WebConfigCase) -> str:
    status = case.status_code if case.status_code is not None else "-"
    lines = [f"HTTP {status}"]
    lines.extend(f"{key}: {value}" for key, value in sorted(case.response_headers.items()))
    if case.response_body:
        lines.extend(["", case.response_body[:2500]])
    return "\n".join(lines)


def _issue_text(case: WebConfigCase) -> str:
    lines = []
    for issue in case.issues:
        header = issue.get("header") or issue.get("check_type")
        value = issue.get("header_value")
        result = f"VALUE: {value}" if value not in (None, "") else "MISSING"
        lines.extend(
            [
                f"[{str(issue.get('severity', '')).upper()}] {header}: {result}",
                f"Reason: {issue.get('reason', '')}",
                f"Fix: {issue.get('remediation', '')}",
                "",
            ]
        )
    return "\n".join(lines)


def web_overlay(case: WebConfigCase, *, full: bool) -> tuple[str, str]:
    top = "0" if full else "260px"
    height = "100vh" if full else "calc(100vh - 260px)"
    css = _BASE_CSS + f"""
#g74-panel {{ top: {top} !important; height: {height} !important; }}
#g74-columns {{ height: calc({height} - 68px) !important; }}
.g74-pre {{ height: calc({height} - 100px) !important; }}
"""
    markup = f"""
<div id="g74-panel">
  <div id="g74-tabs"><b>Burp Suite Professional</b> Target &nbsp; Proxy &nbsp; Repeater</div>
  <div id="g74-target">Target: {_esc(case.display_url)}</div>
  <div id="g74-columns">
    <div class="g74-col"><div class="g74-head">Actual Response Headers</div>
      <pre class="g74-pre">{_esc(_header_text(case))}</pre></div>
    <div class="g74-col"><div class="g74-head">Security Configuration Findings</div>
      <pre class="g74-pre">{_esc(_issue_text(case))}</pre></div>
  </div>
</div>"""
    return css, markup


def _sca_text(case: ScaCase) -> str:
    return "\n".join(
        [
            f"Component: {case.component}",
            f"Installed version: {case.version}",
            f"Severity: {case.severity.upper()}",
            f"Advisory: {case.advisory_id}",
            "",
            case.advisory_summary,
            "",
            f"Remediation: {case.remediation}",
        ]
    )


def sca_overlay(case: ScaCase, *, full: bool) -> tuple[str, str]:
    top = "0" if full else "260px"
    height = "100vh" if full else "calc(100vh - 260px)"
    dependencies = "\n".join(case.dependency_lines) or (
        f"{case.component}:{case.version}\n(dependency-tree source line unavailable)"
    )
    css = _BASE_CSS + f"""
#g74-panel {{ top: {top} !important; height: {height} !important; }}
#g74-columns {{ height: calc({height} - 68px) !important; }}
.g74-pre {{ height: calc({height} - 100px) !important; }}
"""
    markup = f"""
<div id="g74-panel">
  <div id="g74-tabs"><b>Dependency Evidence</b> Gradle &nbsp; OSV &nbsp; Advisory</div>
  <div id="g74-target">{_esc(case.component)}:{_esc(case.version)}</div>
  <div id="g74-columns">
    <div class="g74-col"><div class="g74-head">Gradle Dependency Evidence</div>
      <pre class="g74-pre">{_esc(dependencies)}</pre></div>
    <div class="g74-col"><div class="g74-head">Vulnerability Advisory</div>
      <pre class="g74-pre">{_esc(_sca_text(case))}</pre></div>
  </div>
</div>"""
    return css, markup
