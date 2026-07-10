"""5-2 증거 프레임 한 장을 PNG로 렌더링

스크린샷 1장 = (엔드포인트 × 계정) 노출 1건: 스캐너가 그 요청/응답에서 표시한 마스킹되지 않은 모든 값을 주황색으로 함께 강조
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path

FRAME_WIDTH = 1280
FRAME_HEIGHT = 720
BODY_WINDOW = 4000 

_MASKED_HEADER_NAMES = frozenset({"authorization", "cookie", "set-cookie"})


@dataclass
class ShotSpec:
    tab_label: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status_code: int | None
    response_content_type: str
    response_body_text: str
    severity: str
    category_label: str
    account_label: str
    short_id: str
    captured_at: str
    url_markers: list[str] = field(default_factory=list)
    request_body_markers: list[str] = field(default_factory=list)
    response_body_markers: list[str] = field(default_factory=list)
    note: str = ""


def mask_header_value(name: str, value: str) -> str:
    if name.lower() not in _MASKED_HEADER_NAMES:
        return value
    text = value.strip()
    if len(text) <= 16:
        return "***redacted***"
    return f"{text[:16]}···redacted"


def pretty_body(raw: str | bytes, content_type: str = "") -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    text = text.strip()
    if not text:
        return ""
    if "json" in content_type.lower() or text.startswith("{") or text.startswith("["):
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
    return text


def window_multi(text: str, needles: list[str], *, max_len: int = BODY_WINDOW) -> str:
    """가장 먼저 강조된 값을 기준점으로 삼아 `text`를 `max_len`으로 자름"""
    if len(text) <= max_len:
        return text
    positions = [p for n in needles if n and (p := text.find(n)) != -1]
    if not positions:
        return text[:max_len].rstrip() + "\n… (truncated)"
    start = max(0, min(positions) - 40)
    end = min(len(text), start + max_len)
    start = max(0, end - max_len)
    prefix = "… " if start > 0 else ""
    suffix = " …" if end < len(text) else ""
    return prefix + text[start:end] + suffix


def escape_and_mark_multi(text: str, needles: list[str]) -> tuple[str, int]:
    """`text`를 HTML 이스케이프하고, 각 needle의 모든 등장 위치를 <mark>로 감쌈,
    긴 needle을 먼저 토큰화하여, 긴 값의 부분 문자열인 짧은 값이 이중으로 감싸지지 않게 함,
    (html, 표시된 고유 needle 수)를 반환
    """
    uniq = sorted({n for n in needles if n}, key=len, reverse=True)
    if not uniq:
        return html.escape(text, quote=False), 0

    marked = text
    tokens: dict[str, str] = {}
    hit = 0
    for i, needle in enumerate(uniq):
        if needle not in marked:
            continue
        token = f"\x00MARK{i}\x00"
        tokens[token] = needle
        marked = marked.replace(needle, token)
        hit += 1

    escaped = html.escape(marked, quote=False)
    for token, needle in tokens.items():
        escaped = escaped.replace(token, f"<mark>{html.escape(needle, quote=False)}</mark>")
    return escaped, hit


_SEV_CLASS = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low"}


def _severity_chip(severity: str) -> str:
    cls = _SEV_CLASS.get(severity.lower(), "sev-low")
    return f'<span class="sev {cls}">{html.escape(severity)}</span>'


def _split_url(url: str) -> tuple[str, str, str]:
    if "://" not in url:
        return "", "", url
    scheme, rest = url.split("://", 1)
    if "/" in rest:
        host, path = rest.split("/", 1)
        return scheme, host, "/" + path
    return scheme, rest, ""


def render_html(spec: ShotSpec) -> str:
    scheme, host, path = _split_url(spec.url)
    is_https = scheme.lower() == "https"
    lock_icon = "🔒" if is_https else "⚠️"

    url_plain = f"{scheme}://{host}{path}"
    url_html, _ = escape_and_mark_multi(url_plain, spec.url_markers)

    req_headers_lines = "\n".join(
        f"{k}: {mask_header_value(k, v)}" for k, v in spec.request_headers.items()
    )

    req_body_windowed = window_multi(spec.request_body, spec.request_body_markers) if spec.request_body else ""
    req_body_html, _ = escape_and_mark_multi(req_body_windowed, spec.request_body_markers)

    resp_body_windowed = (
        window_multi(spec.response_body_text, spec.response_body_markers) if spec.response_body_text else ""
    )
    resp_body_html, _ = escape_and_mark_multi(resp_body_windowed, spec.response_body_markers)

    start_line_html, _ = escape_and_mark_multi(f"{spec.method} {path or '/'}", spec.url_markers)

    status = spec.status_code if spec.status_code is not None else "—"
    status_class = "status-ok" if (spec.status_code or 0) < 400 else "status-err"

    request_body_block = (
        f'<div class="subhead">Body</div><pre>{req_body_html}</pre>' if spec.request_body else ""
    )
    response_body_block = (
        f'<div class="subhead">Body</div><pre>{resp_body_html}</pre>'
        if spec.response_body_text
        else '<div class="subhead">Body</div><pre class="empty">(empty body)</pre>'
    )
    note_html = f'<div class="note">{html.escape(spec.note)}</div>' if spec.note else ""

    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<title>ARGUS 5-2 evidence</title>
<style>
  :root {{
    --ink: #cbd5e1;
    --ink-dim: #6b7994;
    --ink-bright: #eef2f8;
    --accent-cyan: #63d9e8;
    --accent-violet: #9d8cf5;
    --frame-bg: #0d1420;
    --chrome-bg: #171f2e;
    --chrome-border: #263349;
    --card-bg: #121a28;
    --card-border: #243045;
    --code-bg: #0a101c;
    --code-border: #1c2740;
    --sans: "Segoe UI", -apple-system, "Malgun Gothic", system-ui, sans-serif;
    --mono: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0; padding: 0;
    width: {FRAME_WIDTH}px; height: {FRAME_HEIGHT}px;
    background: var(--frame-bg);
    font-family: var(--sans);
    overflow: hidden;
  }}
  .frame {{ width: {FRAME_WIDTH}px; height: {FRAME_HEIGHT}px; display: flex; flex-direction: column; }}
  .chrome {{ flex: 0 0 auto; background: var(--chrome-bg); border-bottom: 1px solid var(--chrome-border); }}
  .tabstrip {{ display: flex; align-items: center; gap: 8px; padding: 10px 14px 0; }}
  .traffic {{ display: flex; gap: 7px; padding-bottom: 10px; margin-right: 4px; }}
  .traffic i {{ width: 11px; height: 11px; border-radius: 50%; display: block; }}
  .traffic i:nth-child(1) {{ background: #ec6a5e; }}
  .traffic i:nth-child(2) {{ background: #f4bf4f; }}
  .traffic i:nth-child(3) {{ background: #61c454; }}
  .tab {{ display: flex; align-items: center; gap: 7px; background: var(--frame-bg);
    border-radius: 8px 8px 0 0; padding: 7px 16px 9px; font-size: 0.78rem; color: var(--ink); max-width: 460px; }}
  .tab .favicon {{ width: 13px; height: 13px; border-radius: 3px;
    background: linear-gradient(135deg, var(--accent-violet), var(--accent-cyan)); flex: 0 0 auto; }}
  .tab span {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .addressbar {{ display: flex; align-items: center; gap: 10px; padding: 9px 14px 11px; }}
  .addressbar .nav {{ display: flex; gap: 10px; color: var(--ink-dim); font-size: 0.85rem; }}
  .addressbar .pill {{ flex: 1; display: flex; align-items: center; gap: 8px; background: var(--frame-bg);
    border: 1px solid var(--chrome-border); border-radius: 999px; padding: 6px 14px;
    font-family: var(--mono); font-size: 0.76rem; color: var(--ink); min-width: 0; }}
  .addressbar .pill .url-text {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .evidence {{ flex: 1 1 auto; padding: 16px 26px 18px; display: flex; flex-direction: column; gap: 11px; min-height: 0; }}
  .meta {{ display: flex; align-items: center; gap: 10px; flex: 0 0 auto; flex-wrap: wrap; }}
  .badge {{ font-family: var(--mono); font-size: 0.72rem; color: var(--accent-cyan);
    background: rgba(99, 217, 232, 0.1); border: 1px solid rgba(99, 217, 232, 0.25); border-radius: 5px; padding: 3px 8px; }}
  .sev {{ font-family: var(--mono); font-size: 0.7rem; font-weight: 600; letter-spacing: 0.04em;
    text-transform: uppercase; border-radius: 5px; padding: 3px 8px; }}
  .sev-high {{ color: #ffd9d9; background: rgba(243, 104, 104, 0.18); border: 1px solid rgba(243, 104, 104, 0.4); }}
  .sev-medium {{ color: #ffe9c2; background: rgba(245, 185, 66, 0.16); border: 1px solid rgba(245, 185, 66, 0.4); }}
  .sev-low {{ color: #dbe6f5; background: rgba(127, 168, 201, 0.16); border: 1px solid rgba(127, 168, 201, 0.4); }}
  .account {{ font-family: var(--mono); font-size: 0.72rem; color: var(--ink-bright);
    background: rgba(157, 140, 245, 0.12); border: 1px solid rgba(157, 140, 245, 0.3); border-radius: 5px; padding: 3px 8px; }}
  .meta .cats {{ font-family: var(--mono); font-size: 0.72rem; color: var(--ink-dim); }}
  .meta .spacer {{ flex: 1; }}
  .meta .stamp {{ font-family: var(--mono); font-size: 0.68rem; color: var(--ink-dim); }}
  .panels {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; flex: 1 1 auto; min-height: 0; }}
  .panel {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px;
    padding: 13px 15px; display: flex; flex-direction: column; gap: 9px; min-height: 0; overflow: hidden; }}
  .panel h3 {{ margin: 0; font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--ink-dim); font-weight: 600; display: flex; align-items: center; gap: 8px; }}
  .panel h3 .dot {{ height: 4px; width: 4px; border-radius: 50%; background: var(--accent-violet); }}
  .panel .startline {{ font-family: var(--mono); font-size: 0.78rem; color: var(--ink-bright);
    background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 6px; padding: 7px 10px; word-break: break-all; }}
  .panel .startline .method {{ color: var(--accent-cyan); font-weight: 700; margin-right: 8px; }}
  .panel .startline .status-ok {{ color: #7fd99a; font-weight: 700; margin-right: 8px; }}
  .panel .startline .status-err {{ color: #f5a3a3; font-weight: 700; margin-right: 8px; }}
  .panel pre {{ margin: 0; flex: 1 1 auto; background: var(--code-bg); border: 1px solid var(--code-border);
    border-radius: 6px; padding: 10px 12px; font-family: var(--mono); font-size: 0.74rem; color: var(--ink);
    overflow: hidden; white-space: pre-wrap; word-break: break-word; }}
  .panel pre.empty {{ color: var(--ink-dim); font-style: italic; }}
  .panel .subhead {{ font-family: var(--mono); font-size: 0.66rem; color: var(--ink-dim); letter-spacing: 0.03em; }}
  mark {{ background: rgba(251, 146, 60, 0.28); color: #ffcb96; border: 1px solid rgba(251, 146, 60, 0.55);
    border-radius: 3px; padding: 0 3px; font-weight: 600; }}
  .note {{ font-family: var(--mono); font-size: 0.66rem; color: var(--ink-dim); flex: 0 0 auto; }}
</style>
</head>
<body>
  <div class="frame">
    <div class="chrome">
      <div class="tabstrip">
        <div class="traffic"><i></i><i></i><i></i></div>
        <div class="tab"><span class="favicon"></span><span>{html.escape(spec.tab_label)}</span></div>
      </div>
      <div class="addressbar">
        <div class="nav">‹&nbsp;&nbsp;›&nbsp;&nbsp;↻</div>
        <div class="pill">
          <span>{lock_icon}</span>
          <span class="url-text">{url_html}</span>
        </div>
      </div>
    </div>

    <div class="evidence">
      <div class="meta">
        <span class="badge">5-2</span>
        {_severity_chip(spec.severity)}
        <span class="account">{html.escape(spec.account_label)}</span>
        <span class="cats">노출: {html.escape(spec.category_label)} · #{html.escape(spec.short_id)}</span>
        <div class="spacer"></div>
        <span class="stamp">captured {html.escape(spec.captured_at)}</span>
      </div>

      <div class="panels">
        <div class="panel">
          <h3><span class="dot"></span>Request</h3>
          <div class="startline"><span class="method">{html.escape(spec.method)}</span>{start_line_html}</div>
          <div class="subhead">Headers</div>
          <pre>{html.escape(req_headers_lines)}</pre>
          {request_body_block}
        </div>
        <div class="panel">
          <h3><span class="dot"></span>Response</h3>
          <div class="startline"><span class="{status_class}">HTTP {html.escape(str(status))}</span>{html.escape(spec.response_content_type)}</div>
          {response_body_block}
        </div>
      </div>
      {note_html}
    </div>
  </div>
</body>
</html>
"""


class ScreenshotBrowser:
    """재사용 가능한 헤드리스 Chromium 세션 — 캡처 배치 전체를 한 번의 실행으로 처리"""

    def __init__(self) -> None:
        self._pw = None
        self._browser = None
        self._page = None

    def __enter__(self) -> "ScreenshotBrowser":
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._page = self._browser.new_page(viewport={"width": FRAME_WIDTH, "height": FRAME_HEIGHT})
        return self

    def __exit__(self, *_args: object) -> None:
        if self._browser:
            self._browser.close()
        if self._pw:
            self._pw.stop()

    def capture(self, html_content: str, out_path: Path) -> None:
        assert self._page is not None
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._page.set_content(html_content, wait_until="load")
        self._page.screenshot(path=str(out_path))
