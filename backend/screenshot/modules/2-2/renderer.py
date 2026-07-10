"""Render deterministic 1280x720 evidence boards / overlays for 2-2."""

from __future__ import annotations

import html
import json

from models import EvidenceCase, HttpExchange
from redaction import redact_headers, redact_text

RULE_LABELS = {
    "2-2-path-traversal": "경로 조작 · 파일 노출",
    "2-2-input-validation": "입력값 검증 미흡",
    "2-2-unauth-download": "비로그인 다운로드",
    "2-2-forced-browse": "강제 파일 탐색",
    "2-2-idor": "IDOR / 타 계정 접근",
}


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _request(exchange: HttpExchange) -> str:
    lines = [f"{exchange.method.upper()} {exchange.display_url or exchange.url} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in redact_headers(exchange.request_headers).items())
    if exchange.request_body:
        lines.extend(["", redact_text(exchange.request_body)])
    return "\n".join(lines)


def _response_body_for_display(exchange: HttpExchange) -> str:
    """Avoid dumping PDF/binary as UTF-8 mojibake in evidence panels."""
    from file_compare import looks_like_download, _preview_text, _filename, _header

    raw = exchange.response_body_raw or b""
    headers = exchange.response_headers or {}
    if raw and looks_like_download(exchange):
        filename = _filename(headers) or "-"
        ctype = _header(headers, "content-type") or "-"
        preview = _preview_text(raw, headers)
        return (
            f"[download body]\n"
            f"filename: {filename}\n"
            f"content-type: {ctype}\n"
            f"size: {len(raw)} bytes\n"
            f"\n---- extracted / preview ----\n"
            f"{preview}"
        )
    if exchange.response_body:
        # Guard: if text looks like binary mojibake, prefer raw preview path.
        sample = exchange.response_body[:800]
        replacement = sample.count("\ufffd")
        if replacement >= 8 or "endobj" in sample or "endstream" in sample:
            if raw:
                return _preview_text(raw, headers)
        return redact_text(exchange.response_body)
    return ""


def _response(exchange: HttpExchange) -> str:
    lines = [f"HTTP {exchange.status_code if exchange.status_code is not None else '-'}"]
    lines.extend(f"{k}: {v}" for k, v in redact_headers(exchange.response_headers).items())
    body = _response_body_for_display(exchange)
    if body:
        lines.extend(["", body])
    return "\n".join(lines)


def _metric(exchange: HttpExchange) -> str:
    elapsed = "-" if exchange.elapsed_ms is None else f"{exchange.elapsed_ms:.0f} ms"
    body_len = len(exchange.response_body_raw or b"") or len(exchange.response_body or "")
    return f"status={exchange.status_code or '-'} · time={elapsed} · body={body_len} bytes"


def _panel_titles(case: EvidenceCase, kind: str) -> tuple[str, str, str, str]:
    """Return left_title, right_title, summary, target_url for a board kind."""
    rule_label = RULE_LABELS.get(case.rule_id, case.rule_id)
    unauth = case.rule_id == "2-2-unauth-download"

    if kind == "baseline":
        if unauth:
            return (
                "Authenticated Request",
                "Authenticated Response",
                f"정상(로그인) 요청 · {_metric(case.baseline)}",
                case.baseline.display_url or case.baseline.url,
            )
        return (
            "Baseline Request",
            "Baseline Response",
            f"정상 요청 기준값 · {_metric(case.baseline)}",
            case.baseline.display_url or case.baseline.url,
        )
    if kind == "attack":
        if unauth:
            return (
                "Unauthenticated Request",
                "Unauthenticated Response",
                f"비인증 요청 · {_metric(case.attack)}",
                case.attack.display_url or case.attack.url,
            )
        return (
            "Exploit Request",
            "Exploit Response",
            (
                f"공격 재현 · rule={rule_label} · parameter={case.parameter or '-'} · "
                f"payload={case.payload or '-'} · trigger={case.trigger or '-'} · {_metric(case.attack)}"
            ),
            case.attack.display_url or case.attack.url,
        )
    if kind == "comparison":
        if unauth:
            return (
                "Authenticated",
                "Unauthenticated",
                (
                    f"응답 비교 · {rule_label} · auth={case.baseline.status_code or '-'} · "
                    f"anon={case.attack.status_code or '-'} · trigger={case.trigger or '-'}"
                ),
                case.attack.display_url or case.attack.url,
            )
        return (
            "Baseline",
            "Exploit",
            (
                f"응답 비교 · {rule_label} · trigger={case.trigger or '-'} · "
                f"parameter={case.parameter or '-'}"
            ),
            case.attack.display_url or case.attack.url,
        )
    raise ValueError(f"Unknown evidence kind: {kind}")


def _panel_bodies(case: EvidenceCase, kind: str) -> tuple[str, str]:
    if kind == "baseline":
        return _request(case.baseline), _response(case.baseline)
    if kind == "attack":
        return _request(case.attack), _response(case.attack)
    if kind == "comparison":
        left = f"{_metric(case.baseline)}\n\n{_request(case.baseline)}\n\n{_response(case.baseline)}"
        right = f"{_metric(case.attack)}\n\n{_request(case.attack)}\n\n{_response(case.attack)}"
        return left, right
    raise ValueError(f"Unknown evidence kind: {kind}")


def render_evidence_html(case: EvidenceCase, kind: str) -> str:
    left_title, right_title, summary, shown_url = _panel_titles(case, kind)
    left, right = _panel_bodies(case, kind)
    rule_label = RULE_LABELS.get(case.rule_id, case.rule_id)
    metadata = redact_text(json.dumps(case.metadata, ensure_ascii=False, sort_keys=True))
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
</style>
</head>
<body>
  <section class="chrome">
    <div class="tab">ARGUS Evidence · {_esc(case.finding_id)}</div>
    <div class="url">{_esc(shown_url)}</div>
  </section>
  <section class="hero">
    <div class="badges"><span>{_esc(case.section_id)}</span><span>{_esc(kind.upper())}</span>
      <span>{_esc(rule_label)}</span></div>
    <h1>{_esc(case.title)}</h1>
    <div class="summary">{_esc(summary)}</div>
    <div class="meta">{_esc(metadata)}</div>
  </section>
  <section class="bar">{_esc(left_title)} / {_esc(right_title)}</section>
  <section class="panels">
    <div class="panel">
      <div class="panel-title">{_esc(left_title)}</div>
      <pre>{_esc(left)}</pre>
    </div>
    <div class="panel">
      <div class="panel-title">{_esc(right_title)}</div>
      <pre>{_esc(right)}</pre>
    </div>
  </section>
</body>
</html>"""


def render_evidence_overlay(case: EvidenceCase, kind: str) -> tuple[str, str]:
    """Return isolated CSS/HTML overlaid on top of the discovered target page."""
    left_title, right_title, _summary, target = _panel_titles(case, kind)
    left, right = _panel_bodies(case, kind)
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


def render_comparison_overlay(case: EvidenceCase) -> tuple[str, str]:
    """Full-height comparison board for authenticated vs unauthenticated responses."""
    css, markup = render_evidence_overlay(case, "comparison")
    css += """
#argus-evidence-bottom { top: 0 !important; height: 100vh !important; }
#argus-evidence-panels { height: calc(100vh - 70px) !important; }
.argus-evidence-pre { height: calc(100vh - 100px) !important; font-size: 11.5px !important; line-height: 1.5 !important; }
"""
    return css, markup


def _file_side_text(side: dict) -> str:
    lines = [
        f"status: {side.get('status') or '-'}",
        f"filename: {side.get('filename') or '-'}",
        f"content-type: {side.get('content_type') or '-'}",
        f"content-disposition: {side.get('content_disposition') or '-'}",
        f"size: {side.get('size') or 0} bytes",
        f"sha256: {side.get('sha256') or '-'}",
        "",
        "---- content preview ----",
        str(side.get("preview") or "(no preview)"),
    ]
    return "\n".join(lines)


def render_file_compare_overlay(case: EvidenceCase) -> tuple[str, str]:
    """Full-height board comparing downloaded file contents (baseline vs exploit or auth vs anon)."""
    detail = dict(case.metadata.get("file_compare_detail") or {})
    left_side = dict(
        detail.get("left") or detail.get("auth") or detail.get("baseline") or {}
    )
    right_side = dict(
        detail.get("right") or detail.get("anon") or detail.get("attack") or {}
    )
    mode = str(detail.get("mode") or "auth_vs_anon")
    if mode == "baseline_vs_attack":
        subtitle = str(detail.get("subtitle") or "Baseline vs Exploit")
        left_heading = str(detail.get("left_heading") or "Baseline File (정상)")
        right_heading = str(detail.get("right_heading") or "Exploit File (공격)")
    else:
        subtitle = str(detail.get("subtitle") or "Auth vs Anon")
        left_heading = str(detail.get("left_heading") or "Authenticated File")
        right_heading = str(detail.get("right_heading") or "Unauthenticated File")
    target = case.attack.display_url or case.baseline.display_url or case.attack.url or "/"
    left = _file_side_text(left_side)
    right = _file_side_text(right_side)
    css = """
#argus-evidence-root, #argus-evidence-root * { box-sizing: border-box !important; }
#argus-evidence-root { position: fixed !important; inset: 0 !important; z-index: 2147483647 !important;
  pointer-events: none !important; font-family: Arial, "Noto Sans KR", sans-serif !important; }
#argus-evidence-bottom { position: absolute !important; top: 0 !important; left: 0 !important;
  width: 100vw !important; height: 100vh !important; background: #111315 !important;
  color: #e4e8ec !important; border-top: 4px solid #e7782f !important; }
#argus-evidence-tabs { height: 32px !important; padding: 7px 12px !important; background: #25282c !important;
  color: #aaa !important; font-size: 12px !important; font-weight: 700 !important; }
#argus-evidence-tabs b { color: #ef873e !important; margin-right: 22px !important; }
#argus-evidence-target { height: 34px !important; padding: 8px 12px !important; background: #191b1e !important;
  border-top: 1px solid #393d42 !important; border-bottom: 1px solid #393d42 !important;
  color: #d4d8dd !important; font: 12px ui-monospace, monospace !important; white-space: nowrap !important;
  overflow: hidden !important; text-overflow: ellipsis !important; }
#argus-evidence-panels { display: grid !important; grid-template-columns: 1fr 1fr !important;
  height: calc(100vh - 70px) !important; }
.argus-evidence-panel { min-width: 0 !important; border-right: 1px solid #383c41 !important;
  background: #111315 !important; }
.argus-evidence-heading { height: 30px !important; padding: 8px 11px !important; background: #25282c !important;
  color: #72d68b !important; font-size: 12px !important; font-weight: 700 !important; }
.argus-evidence-pre { height: calc(100vh - 100px) !important; margin: 0 !important; padding: 12px !important;
  overflow: hidden !important; color: #d8dde2 !important; white-space: pre-wrap !important;
  overflow-wrap: anywhere !important; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace !important; }
"""
    markup = f"""
<div id="argus-evidence-bottom">
  <div id="argus-evidence-tabs"><b>File Content Compare</b> {_esc(subtitle)}</div>
  <div id="argus-evidence-target">Target: {_esc(target)}</div>
  <div id="argus-evidence-panels">
    <div class="argus-evidence-panel"><div class="argus-evidence-heading">{_esc(left_heading)}</div>
      <pre class="argus-evidence-pre">{_esc(left)}</pre></div>
    <div class="argus-evidence-panel"><div class="argus-evidence-heading">{_esc(right_heading)}</div>
      <pre class="argus-evidence-pre">{_esc(right)}</pre></div>
  </div>
</div>"""
    return css, markup
