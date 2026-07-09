"""Render a deterministic 1280x720 evidence board."""

from __future__ import annotations

import html
import json

from models import EvidenceCase, HttpExchange
from redaction import redact_headers, redact_text


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _request(exchange: HttpExchange) -> str:
    lines = [f"{exchange.method.upper()} {exchange.display_url or exchange.url} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in redact_headers(exchange.request_headers).items())
    if exchange.request_body:
        lines.extend(["", redact_text(exchange.request_body)])
    return "\n".join(lines)


def _response(exchange: HttpExchange) -> str:
    lines = [f"HTTP {exchange.status_code if exchange.status_code is not None else '-'}"]
    lines.extend(f"{k}: {v}" for k, v in redact_headers(exchange.response_headers).items())
    if exchange.response_body:
        lines.extend(["", redact_text(exchange.response_body)])
    return "\n".join(lines)


def _metric(exchange: HttpExchange) -> str:
    elapsed = "-" if exchange.elapsed_ms is None else f"{exchange.elapsed_ms:.0f} ms"
    return f"status={exchange.status_code or '-'} · time={elapsed} · body={len(exchange.response_body)} bytes"


def render_evidence_html(case: EvidenceCase, kind: str) -> str:
    if kind == "baseline":
        left_title, right_title = "Baseline Request", "Baseline Response"
        left, right = _request(case.baseline), _response(case.baseline)
        summary = f"정상 요청 기준값 · {_metric(case.baseline)}"
    elif kind == "attack":
        left_title, right_title = "Attack Request", "Attack Response"
        left, right = _request(case.attack), _response(case.attack)
        summary = f"공격 재현 · parameter={case.parameter} · payload={case.payload} · {_metric(case.attack)}"
    elif kind == "comparison":
        left_title, right_title = "Baseline", "Attack"
        left = f"{_metric(case.baseline)}\n\n{_response(case.baseline)}"
        right = f"{_metric(case.attack)}\n\n{_response(case.attack)}"
        summary = (
            f"비교 판정 · {case.verification_type} · confidence={case.confidence} · "
            f"parameter={case.parameter}"
        )
    else:
        raise ValueError(f"Unknown evidence kind: {kind}")

    metadata = redact_text(json.dumps(case.metadata, ensure_ascii=False, sort_keys=True))
    shown_exchange = case.attack if kind == "attack" else case.baseline
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<style>
* {{ box-sizing: border-box; }}
html, body {{ width: 1280px; height: 720px; margin: 0; overflow: hidden; }}
body {{ background: #111418; color: #e8edf2; font-family: Arial, "Noto Sans KR", sans-serif; }}
.chrome {{ height: 76px; padding: 10px 18px; background: #eef1f4; color: #20242a; }}
.tab {{ font-size: 13px; margin-bottom: 7px; color: #49515a; }}
.url {{ height: 32px; border: 1px solid #c8ced6; border-radius: 17px; background: white;
        padding: 7px 15px; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace;
        overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
.hero {{ height: 214px; padding: 22px 26px; background: linear-gradient(135deg, #26384e, #17212d); }}
.badges span {{ display: inline-block; margin-right: 7px; padding: 5px 9px; border-radius: 5px;
                background: #334b68; font-size: 12px; }}
h1 {{ margin: 18px 0 8px; font-size: 25px; }}
.summary {{ color: #b8c9da; font-size: 14px; }}
.meta {{ margin-top: 18px; color: #7890a8; font: 11px ui-monospace, monospace;
         overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
.bar {{ height: 46px; padding: 13px 18px; border-top: 3px solid #ec7c32; background: #202328;
        font-size: 14px; font-weight: 700; }}
.panels {{ display: grid; grid-template-columns: 1fr 1fr; height: 384px; }}
.panel {{ min-width: 0; border-right: 1px solid #394049; background: #121417; }}
.panel-title {{ height: 38px; padding: 11px 14px; color: #7bd88f; background: #25292e;
                font-size: 13px; font-weight: 700; }}
pre {{ height: 346px; margin: 0; padding: 14px; overflow: hidden; white-space: pre-wrap;
       overflow-wrap: anywhere; color: #d5dbe2; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }}
.payload {{ color: #ffad66; }}
</style>
</head>
<body>
  <section class="chrome">
    <div class="tab">ARGUS Evidence · {_esc(case.finding_id)}</div>
    <div class="url">{_esc(shown_exchange.display_url or shown_exchange.url)}</div>
  </section>
  <section class="hero">
    <div class="badges"><span>{_esc(case.section_id)}</span><span>{_esc(kind.upper())}</span>
      <span>{_esc(case.confidence.upper())}</span></div>
    <h1>{_esc(case.title)}</h1>
    <div class="summary">{_esc(summary)}</div>
    <div class="meta">{_esc(metadata)}</div>
  </section>
  <div class="bar">Request / Response Evidence</div>
  <section class="panels">
    <div class="panel"><div class="panel-title">{_esc(left_title)}</div><pre>{_esc(left)}</pre></div>
    <div class="panel"><div class="panel-title">{_esc(right_title)}</div><pre>{_esc(right)}</pre></div>
  </section>
</body>
</html>"""


def render_evidence_overlay(case: EvidenceCase, kind: str) -> tuple[str, str]:
    """Return isolated CSS/HTML overlaid on top of the real ONDE page."""
    if kind == "baseline":
        left_title, right_title = "Request", "Response"
        left, right = _request(case.baseline), _response(case.baseline)
        target = case.baseline.display_url or case.baseline.url
    elif kind == "attack":
        left_title, right_title = "Request", "Response"
        left, right = _request(case.attack), _response(case.attack)
        target = case.attack.display_url or case.attack.url
    elif kind == "comparison":
        left_title, right_title = "Baseline", "Attack"
        left = f"{_metric(case.baseline)}\n\n{_request(case.baseline)}\n\n{_response(case.baseline)}"
        right = f"{_metric(case.attack)}\n\n{_request(case.attack)}\n\n{_response(case.attack)}"
        target = case.attack.display_url or case.attack.url
    else:
        raise ValueError(f"Unknown evidence kind: {kind}")

    browser_url = str(case.metadata.get("ui_display_url") or "http://localhost:5173/")
    css = """
#argus-evidence-root, #argus-evidence-root * { box-sizing: border-box !important; }
#argus-evidence-root { position: fixed !important; inset: 0 !important; z-index: 2147483647 !important;
  pointer-events: none !important; font-family: Arial, "Noto Sans KR", sans-serif !important; }
#argus-evidence-bottom { position: absolute !important; top: 260px !important; left: 0 !important;
  width: 100vw !important; height: calc(100vh - 260px) !important; background: #111315 !important;
  color: #e4e8ec !important; border-top: 4px solid #e7782f !important; }
#argus-evidence-tabs { height: 32px !important; padding: 7px 12px !important; background: #25282c !important;
  color: #aaa !important; font-size: 12px !important; font-weight: 700 !important; }
#argus-evidence-tabs b { color: #ef873e !important; margin-right: 22px !important; }
#argus-evidence-target { height: 34px !important; padding: 8px 12px !important; background: #191b1e !important;
  border-top: 1px solid #393d42 !important; border-bottom: 1px solid #393d42 !important;
  color: #d4d8dd !important; font: 12px ui-monospace, monospace !important; white-space: nowrap !important;
  overflow: hidden !important; text-overflow: ellipsis !important; }
#argus-evidence-panels { display: grid !important; grid-template-columns: 1fr 1fr !important;
  height: calc(100vh - 330px) !important; }
.argus-evidence-panel { min-width: 0 !important; border-right: 1px solid #383c41 !important;
  background: #111315 !important; }
.argus-evidence-heading { height: 30px !important; padding: 8px 11px !important; background: #25282c !important;
  color: #72d68b !important; font-size: 12px !important; font-weight: 700 !important; }
.argus-evidence-pre { height: calc(100vh - 360px) !important; margin: 0 !important; padding: 12px !important;
  overflow: hidden !important; color: #d8dde2 !important; white-space: pre-wrap !important;
  overflow-wrap: anywhere !important; font: 10.5px/1.42 ui-monospace, SFMono-Regular, Menlo, monospace !important; }
"""
    markup = f"""
<div id="argus-evidence-bottom">
  <div id="argus-evidence-tabs"><b>Burp Suite Professional</b> Target &nbsp; Proxy &nbsp; Intruder &nbsp; Repeater</div>
  <div id="argus-evidence-target">Target: {_esc(target)}</div>
  <div id="argus-evidence-panels">
    <div class="argus-evidence-panel"><div class="argus-evidence-heading">{_esc(left_title)}</div>
      <pre class="argus-evidence-pre">{_esc(left)}</pre></div>
    <div class="argus-evidence-panel"><div class="argus-evidence-heading">{_esc(right_title)}</div>
      <pre class="argus-evidence-pre">{_esc(right)}</pre></div>
  </div>
</div>"""
    return css, markup


def render_url_overlay(case: EvidenceCase) -> tuple[str, str]:
    """Browser-like URL strip for a site-only evidence screenshot."""
    browser_url = str(case.metadata.get("ui_display_url") or "http://localhost:5173/")
    css = """
#argus-evidence-root, #argus-evidence-root * { box-sizing: border-box !important; }
#argus-evidence-root { position: fixed !important; inset: 0 !important; z-index: 2147483647 !important;
  pointer-events: none !important; }
#argus-evidence-top { position: absolute !important; top: 0 !important; left: 0 !important;
  width: 1280px !important; height: 56px !important; padding: 11px 18px !important;
  background: #eef1f4 !important; border-bottom: 1px solid #c9cfd6 !important; }
#argus-evidence-url { height: 34px !important; padding: 8px 15px !important; border-radius: 18px !important;
  border: 1px solid #c6ccd3 !important; background: #fff !important; color: #252a30 !important;
  font: 13px ui-monospace, SFMono-Regular, Menlo, monospace !important; white-space: nowrap !important;
  overflow: hidden !important; text-overflow: ellipsis !important; }
"""
    markup = (
        f'<div id="argus-evidence-top"><div id="argus-evidence-url">'
        f"{_esc(browser_url)}</div></div>"
    )
    return css, markup


def render_burp_only(case: EvidenceCase) -> tuple[str, str]:
    """Full evidence screenshot focused on the injected request and response."""
    css, markup = render_evidence_overlay(case, "attack")
    css += """
#argus-evidence-bottom { top: 0 !important; height: 100vh !important; }
#argus-evidence-panels { height: calc(100vh - 70px) !important; }
.argus-evidence-pre { height: calc(100vh - 100px) !important; font-size: 11.5px !important; line-height: 1.5 !important; }
"""
    return css, markup
