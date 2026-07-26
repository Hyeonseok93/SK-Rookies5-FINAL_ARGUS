"""4-4 증거 프레임을 1280x720 PNG로 렌더링

* HTTP 프레임 — Burp 스타일 요청/응답 분할. 요청 패널에 인증 헤더(Authorization/Cookie/…)의 유무를 명시, 
  API 엔드포인트와 "정상(인증)" 기준 프레임에 사용
* Page 프레임 — 프론트엔드 페이지를 실제 익명 브라우저로 렌더한 이미지를 <img>로 삽입해, 
  로그인이 필요한 화면이 인증 없이도 실제로 그려짐을 증명

각 finding은 한 쌍을 만듦: 
기본(정상) 프레임 — 유효 세션으로 접근한 페이지(권한있는 정상 접근)
비교(비정상) 프레임 — 자격증명 없이 접근했는데도 보호 콘텐츠가 노출되는 동일 페이지(취약점)
"""

from __future__ import annotations

import base64
import html
import json
from dataclasses import dataclass, field
from pathlib import Path

FRAME_WIDTH = 1280
FRAME_HEIGHT = 720
PAGE_VIEWPORT = (1280, 600)  # 프론트엔드 렌더 영역. 크롬 + 메타 바가 상단 120px를 차지
BODY_WINDOW = 4000

_AUTH_HEADER_NAMES = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token"}
)
_MASKED_HEADER_NAMES = frozenset({"authorization", "cookie", "set-cookie"})


@dataclass
class FrameSpec:
    """증거 프레임 한 장. `page_png_b64`가 있으면 삽입된 페이지 렌더로 그림"""

    # 프레이밍 / 라벨
    frame_role: str  # 표시 라벨, 예: "정상 접근 (인증)" / "비정상 접근 (비인증)"
    role_kind: str  # "normal" | "abnormal" | "expected"
    case_label: str  # trigger 라벨, 예: "비인증 중요 페이지 접근 확인"
    severity: str
    account_label: str
    short_id: str
    captured_at: str
    url: str
    section_badge: str = "4-4"
    # HTTP 증거 (HTTP 프레임)
    method: str = "GET"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: int | None = None
    response_content_type: str = ""
    response_body_text: str = ""
    response_body_markers: list[str] = field(default_factory=list)
    auth_present: bool = False
    note: str = ""
    # 렌더된 페이지 (Page 프레임)
    page_png_b64: str = ""


def has_auth_header(headers: dict[str, str]) -> bool:
    return any(k.lower() in _AUTH_HEADER_NAMES for k in headers)


def png_to_b64(png: bytes) -> str:
    return base64.b64encode(png).decode("ascii")


def mask_header_value(name: str, value: str) -> str:
    if name.lower() not in _MASKED_HEADER_NAMES:
        return value
    text = value.strip()
    if len(text) <= 16:
        return "***redacted***"
    return f"{text[:16]}···redacted"


def pretty_body(raw: str | bytes, content_type: str = "") -> str:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        return ""
    if "json" in content_type.lower() or text.startswith(("{", "[")):
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
    return text


def window_multi(text: str, needles: list[str], *, max_len: int = BODY_WINDOW) -> str:
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


def escape_and_mark_multi(text: str, needles: list[str]) -> str:
    uniq = sorted({n for n in needles if n}, key=len, reverse=True)
    if not uniq:
        return html.escape(text, quote=False)
    marked = text
    tokens: dict[str, str] = {}
    for i, needle in enumerate(uniq):
        if needle not in marked:
            continue
        token = f"\x00MARK{i}\x00"
        tokens[token] = needle
        marked = marked.replace(needle, token)
    escaped = html.escape(marked, quote=False)
    for token, needle in tokens.items():
        escaped = escaped.replace(token, f"<mark>{html.escape(needle, quote=False)}</mark>")
    return escaped


_SEV_CLASS = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low"}
_ROLE_CLASS = {"normal": "role-normal", "abnormal": "role-abnormal", "expected": "role-expected"}


def _severity_chip(severity: str) -> str:
    cls = _SEV_CLASS.get(severity.lower(), "sev-low")
    return f'<span class="sev {cls}">{html.escape(severity)}</span>'


def _role_chip(spec: FrameSpec) -> str:
    cls = _ROLE_CLASS.get(spec.role_kind, "role-normal")
    return f'<span class="role {cls}">{html.escape(spec.frame_role)}</span>'


def _split_url(url: str) -> tuple[str, str, str]:
    if "://" not in url:
        return "", "", url
    scheme, rest = url.split("://", 1)
    if "/" in rest:
        host, path = rest.split("/", 1)
        return scheme, host, "/" + path
    return scheme, rest, ""


_CSS = f"""
  :root {{
    --ink: #cbd5e1; --ink-dim: #6b7994; --ink-bright: #eef2f8;
    --accent-cyan: #63d9e8; --accent-violet: #9d8cf5;
    --frame-bg: #0d1420; --chrome-bg: #171f2e; --chrome-border: #263349;
    --card-bg: #121a28; --card-border: #243045; --code-bg: #0a101c; --code-border: #1c2740;
    --sans: "Segoe UI", -apple-system, "Malgun Gothic", system-ui, sans-serif;
    --mono: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; width: {FRAME_WIDTH}px; height: {FRAME_HEIGHT}px;
    background: var(--frame-bg); font-family: var(--sans); overflow: hidden; }}
  .frame {{ width: {FRAME_WIDTH}px; height: {FRAME_HEIGHT}px; display: flex; flex-direction: column; }}
  .chrome {{ flex: 0 0 auto; background: var(--chrome-bg); border-bottom: 1px solid var(--chrome-border); }}
  .tabstrip {{ display: flex; align-items: center; gap: 8px; padding: 10px 14px 0; }}
  .traffic {{ display: flex; gap: 7px; padding-bottom: 10px; margin-right: 4px; }}
  .traffic i {{ width: 11px; height: 11px; border-radius: 50%; display: block; }}
  .traffic i:nth-child(1) {{ background: #ec6a5e; }}
  .traffic i:nth-child(2) {{ background: #f4bf4f; }}
  .traffic i:nth-child(3) {{ background: #61c454; }}
  .tab {{ display: flex; align-items: center; gap: 7px; background: var(--frame-bg);
    border-radius: 8px 8px 0 0; padding: 7px 16px 9px; font-size: 0.78rem; color: var(--ink); max-width: 520px; }}
  .tab .favicon {{ width: 13px; height: 13px; border-radius: 3px;
    background: linear-gradient(135deg, var(--accent-violet), var(--accent-cyan)); flex: 0 0 auto; }}
  .tab span {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .addressbar {{ display: flex; align-items: center; gap: 10px; padding: 9px 14px 11px; }}
  .addressbar .nav {{ display: flex; gap: 10px; color: var(--ink-dim); font-size: 0.85rem; }}
  .addressbar .pill {{ flex: 1; display: flex; align-items: center; gap: 8px; background: var(--frame-bg);
    border: 1px solid var(--chrome-border); border-radius: 999px; padding: 6px 14px;
    font-family: var(--mono); font-size: 0.76rem; color: var(--ink); min-width: 0; }}
  .addressbar .pill .url-text {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .meta {{ display: flex; align-items: center; gap: 10px; flex: 0 0 auto; flex-wrap: wrap; padding: 12px 26px 0; }}
  .badge {{ font-family: var(--mono); font-size: 0.72rem; color: var(--accent-cyan);
    background: rgba(99,217,232,0.1); border: 1px solid rgba(99,217,232,0.25); border-radius: 5px; padding: 3px 8px; }}
  .sev {{ font-family: var(--mono); font-size: 0.7rem; font-weight: 600; letter-spacing: 0.04em;
    text-transform: uppercase; border-radius: 5px; padding: 3px 8px; }}
  .sev-high {{ color: #ffd9d9; background: rgba(243,104,104,0.18); border: 1px solid rgba(243,104,104,0.4); }}
  .sev-medium {{ color: #ffe9c2; background: rgba(245,185,66,0.16); border: 1px solid rgba(245,185,66,0.4); }}
  .sev-low {{ color: #dbe6f5; background: rgba(127,168,201,0.16); border: 1px solid rgba(127,168,201,0.4); }}
  .role {{ font-family: var(--mono); font-size: 0.72rem; font-weight: 600; border-radius: 5px; padding: 3px 9px; }}
  .role-normal {{ color: #b8f5cd; background: rgba(97,196,84,0.14); border: 1px solid rgba(97,196,84,0.45); }}
  .role-abnormal {{ color: #ffd0d0; background: rgba(243,104,104,0.16); border: 1px solid rgba(243,104,104,0.5); }}
  .role-expected {{ color: #dbe6f5; background: rgba(127,168,201,0.14); border: 1px solid rgba(127,168,201,0.4); }}
  .account {{ font-family: var(--mono); font-size: 0.72rem; color: var(--ink-bright);
    background: rgba(157,140,245,0.12); border: 1px solid rgba(157,140,245,0.3); border-radius: 5px; padding: 3px 8px; }}
  .meta .cats {{ font-family: var(--mono); font-size: 0.72rem; color: var(--ink-dim); }}
  .meta .spacer {{ flex: 1; }}
  .meta .stamp {{ font-family: var(--mono); font-size: 0.68rem; color: var(--ink-dim); }}
  .evidence {{ flex: 1 1 auto; padding: 12px 26px 18px; display: flex; flex-direction: column; gap: 11px; min-height: 0; }}
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
  .authflag {{ font-family: var(--mono); font-size: 0.7rem; border-radius: 6px; padding: 5px 9px; }}
  .authflag.absent {{ color: #ffd0d0; background: rgba(243,104,104,0.14); border: 1px solid rgba(243,104,104,0.45); }}
  .authflag.present {{ color: #b8f5cd; background: rgba(97,196,84,0.12); border: 1px solid rgba(97,196,84,0.4); }}
  .panel pre {{ margin: 0; flex: 1 1 auto; background: var(--code-bg); border: 1px solid var(--code-border);
    border-radius: 6px; padding: 10px 12px; font-family: var(--mono); font-size: 0.74rem; color: var(--ink);
    overflow: hidden; white-space: pre-wrap; word-break: break-word; }}
  .panel pre.empty {{ color: var(--ink-dim); font-style: italic; }}
  .panel .subhead {{ font-family: var(--mono); font-size: 0.66rem; color: var(--ink-dim); letter-spacing: 0.03em; }}
  mark {{ background: rgba(251,146,60,0.28); color: #ffcb96; border: 1px solid rgba(251,146,60,0.55);
    border-radius: 3px; padding: 0 3px; font-weight: 600; }}
  .note {{ font-family: var(--mono); font-size: 0.66rem; color: var(--ink-dim); flex: 0 0 auto; }}
  .pageshot {{ flex: 1 1 auto; min-height: 0; margin: 12px 0 0; border-top: 1px solid var(--chrome-border);
    background: #fff; display: flex; }}
  .pageshot img {{ display: block; width: {FRAME_WIDTH}px; height: {PAGE_VIEWPORT[1]}px; object-fit: cover; object-position: top left; }}
"""


def _chrome_html(spec: FrameSpec) -> str:
    scheme, host, path = _split_url(spec.url)
    lock_icon = "🔒" if scheme.lower() == "https" else "⚠️"
    url_html = escape_and_mark_multi(f"{scheme}://{host}{path}", [])
    tab_label = f"ARGUS · {spec.method} {path or '/'}"
    return f"""
    <div class="chrome">
      <div class="tabstrip">
        <div class="traffic"><i></i><i></i><i></i></div>
        <div class="tab"><span class="favicon"></span><span>{html.escape(tab_label)}</span></div>
      </div>
      <div class="addressbar">
        <div class="nav">‹&nbsp;&nbsp;›&nbsp;&nbsp;↻</div>
        <div class="pill"><span>{lock_icon}</span><span class="url-text">{url_html}</span></div>
      </div>
    </div>"""


def _meta_html(spec: FrameSpec) -> str:
    return f"""
      <div class="meta">
        <span class="badge">{html.escape(spec.section_badge)}</span>
        {_severity_chip(spec.severity)}
        {_role_chip(spec)}
        <span class="account">{html.escape(spec.account_label)}</span>
        <span class="cats">{html.escape(spec.case_label)} · #{html.escape(spec.short_id)}</span>
        <div class="spacer"></div>
        <span class="stamp">captured {html.escape(spec.captured_at)}</span>
      </div>"""


def _doc(css_body: str) -> str:
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8" /><title>ARGUS 4-4 evidence</title>
<style>{_CSS}</style></head><body><div class="frame">{css_body}</div></body></html>"""


def _render_http_frame(spec: FrameSpec) -> str:
    scheme, host, path = _split_url(spec.url)
    req_headers_lines = "\n".join(
        f"{k}: {mask_header_value(k, v)}" for k, v in spec.request_headers.items()
    )
    req_body_html = escape_and_mark_multi(spec.request_body, []) if spec.request_body else ""
    resp_windowed = (
        window_multi(spec.response_body_text, spec.response_body_markers)
        if spec.response_body_text
        else ""
    )
    resp_body_html = escape_and_mark_multi(resp_windowed, spec.response_body_markers)
    start_line_html = escape_and_mark_multi(path or "/", [])

    status = spec.status_code if spec.status_code is not None else "—"
    status_class = "status-ok" if (spec.status_code or 0) < 400 else "status-err"

    if spec.auth_present:
        auth_flag = '<div class="authflag present">🔑 인증 헤더 포함 (Authorization/Cookie 등)</div>'
    else:
        auth_flag = '<div class="authflag absent">⚠ 인증 헤더 없음 (Authorization/Cookie 미포함)</div>'

    request_body_block = (
        f'<div class="subhead">Body</div><pre>{req_body_html}</pre>' if spec.request_body else ""
    )
    response_body_block = (
        f'<div class="subhead">Body</div><pre>{resp_body_html}</pre>'
        if spec.response_body_text
        else '<div class="subhead">Body</div><pre class="empty">(empty body)</pre>'
    )
    note_html = f'<div class="note">{html.escape(spec.note)}</div>' if spec.note else ""

    body = f"""
    {_chrome_html(spec)}
    {_meta_html(spec)}
    <div class="evidence">
      <div class="panels">
        <div class="panel">
          <h3><span class="dot"></span>Request</h3>
          <div class="startline"><span class="method">{html.escape(spec.method)}</span>{start_line_html}</div>
          {auth_flag}
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
    </div>"""
    return _doc(body)


def _render_page_frame(spec: FrameSpec) -> str:
    note_html = f'<div class="note" style="padding:6px 26px 10px">{html.escape(spec.note)}</div>' if spec.note else ""
    body = f"""
    {_chrome_html(spec)}
    {_meta_html(spec)}
    {note_html}
    <div class="pageshot"><img src="data:image/png;base64,{spec.page_png_b64}" alt="rendered page" /></div>"""
    return _doc(body)


def render_html(spec: FrameSpec) -> str:
    return _render_page_frame(spec) if spec.page_png_b64 else _render_http_frame(spec)


class ScreenshotBrowser:
    """재사용 가능한 헤드리스 Chromium 세션 — 캡처 배치마다 한 번만 실행"""

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

    def render_page(self, url: str, *, timeout: float = 15.0) -> bytes | None:
        """쿠키 없는 새 컨텍스트로 `url`에 이동해 뷰포트를 스크린샷

        호출마다 새 컨텍스트를 사용해 익명성을 보장 — 인증 쿠키/스토리지가 새어들지 않음,
        PNG 바이트를 반환하며, 이동 실패 시(타깃 다운, 비-HTML 등) None을 반환
        """
        assert self._browser is not None
        ctx = self._browser.new_context(
            viewport={"width": PAGE_VIEWPORT[0], "height": PAGE_VIEWPORT[1]}
        )
        try:
            page = ctx.new_page()
            page.goto(url, wait_until="load", timeout=timeout * 1000)
            page.wait_for_timeout(400)
            return page.screenshot()
        except Exception:
            return None
        finally:
            ctx.close()

    def capture(self, html_content: str, out_path: Path) -> None:
        assert self._page is not None
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._page.set_content(html_content, wait_until="load")
        self._page.screenshot(path=str(out_path))
