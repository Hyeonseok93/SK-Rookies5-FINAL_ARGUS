"""6-1(오류페이지를 통한 정보 노출 여부) — 진짜 화면 + 진짜 Request/Response 캡처.

diagnosis/modules/6-1 스캐너가 만든 report(``data/report/6-1/latest.yaml`` /
``latest-summary.json``)를 읽어, 대표 finding마다 "실제" 증거 사진 3장(공격 전 /
입력(요청) / 결과)을 만든다.

가짜 브라우저 UI(주소창/탭 모형)나 가짜 "Burp Suite" 브랜딩을 그려붙이지 않는다.
대신 실제로 관측한 값만 사용한다. 가로 폭은 1280px로 고정하고, 세로 길이는
내용에 맞춰 늘어난다 — 고정 높이로 자르면 주소나 본문이 잘리므로, "다 보이게"가
"고정 크기"보다 우선이다:

- **STEP1 공격 전(before)**: 취약 URL을 건드리기 전, 정상 오리진 홈 화면을
  ``page.screenshot(full_page=True)``로 담아 "평소 상태"를 남긴다.
- **STEP2 입력(input)**: 실제로 전송되는 요청을 보여준다. GET은 화면이 보이는
  진짜 Chrome 창을 실제 URL로 이동시킨 뒤 CDP(``Browser.getWindowBounds``)로
  그 창의 실제 OS 좌표를 얻어 ``mss``로 그대로 캡처한 진짜 픽셀 중 주소창/탭
  부분만 잘라 "이 URL로 요청을 보낸다"를 보여준다. POST/PUT/PATCH/DELETE는
  아직 응답이 없는 상태의 Request 패널만 렌더링한다.
- **STEP3 결과(result)**: 같은 요청에서 실제로 관측한 method, URL, 요청/응답
  헤더, 응답 바디를 있는 그대로(꾸밈 없이) 2단 패널로 보여주고, 응답 본문에서
  정보 노출 시그니처(예외/스택트레이스 등)가 실제로 발견됐는지로 판단한
  confirmed/failure_reason을 배너로 함께 남긴다. 고정 높이/overflow 클리핑을
  쓰지 않고 내용에 맞춰 자연스럽게 늘어나게 해서 텍스트가 잘리지 않는다.

POST/PUT/PATCH/DELETE는 브라우저가 그대로 재현할 수 없다 — ``<form method>``는
GET/POST만 가능하고, 폼은 body를 ``application/x-www-form-urlencoded``로 보내서
실제 finding(``Content-Type: application/json``)과 다른 코드 경로를 타
(실측 결과: CORS 오류로 대체됨) 증거로 부적합하다. 그래서 이 경우는 STEP2에서
주소창/본문 캡처 없이 대기 중인 요청 내용만 보여주고, STEP3에서 finding을 만든
것과 동일한 방식(같은 method, 같은 Content-Type)으로 살아있는 서버에 실제 요청을
보내고 받은 진짜 Request/Response를 패널에 채운다.

로그인이 필요한 대상은 ``auth_config``로 인증 정보를 넘기면 캡처 세션 시작 전에
쿠키/헤더를 주입한다. 세 가지 방식을 지원한다 — 이 report를 만든 6-1 스캐너가
이미 사용한 계정을 그대로 재사용하는 설정 기반 로그인(``method="config"``:
data/test-accounts.json + data/login-endpoints.json + config.yaml의 auth: 블록을
읽어 로그인하므로 계정 정보를 다시 입력받을 필요가 없음, 권장), API 토큰 로그인
(``method="api"``: 로그인 API를 직접 호출해 받은 토큰을 이후 모든 요청에 헤더로
붙임), Form 로그인(``method="form"``: 실제 화면이 있는 브라우저로 로그인 폼을
제출해 세션 쿠키를 얻음).

raw findings는 7만 건 이상일 수 있으므로, 원본 YAML 전체를 매번 파싱하지 않고
diagnosis 모듈이 이미 만들어 둔 요약 캐시(latest-summary.json, rule_id 단위로
묶인 group)를 사용한다. 대표 사진은 그룹(케이스)당 기본 3세트.

⚠ 화면이 보이는 진짜 브라우저 창을 실제 OS 레벨로 캡처하기 때문에, 접속 가능한
디스플레이가 있는 환경에서만 동작한다. 물리 모니터가 없는 Docker/CI에서는
``xvfb-run``으로 가상 디스플레이를 띄워서 실행할 것(예:
``xvfb-run -a python screenshot/modules/6-1/run.py``) — Xvfb는 진짜 화면 대신
쓰는 가상 X 서버일 뿐, Chrome은 그 안에 진짜 픽셀을 그리고 mss는 그걸 진짜로
읽어오므로 캡처 자체는 여전히 "진짜"다.

⚠ 반드시 허가된 테스트 환경(개발/스테이징 서버)에서만 실행할 것.
"""

from __future__ import annotations

import ctypes
import html
import importlib.util
import json as json_lib
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from PIL import Image

from diagnosis.paths import section_evidence_dir, section_report_path
from diagnosis.replay.normalize import normalize_url
from diagnosis.result import SectionReport

try:
    from playwright.sync_api import sync_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when playwright isn't installed
    sync_playwright = None
    _PLAYWRIGHT_AVAILABLE = False

try:
    import mss
    import mss.tools

    _MSS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when mss isn't installed
    mss = None
    _MSS_AVAILABLE = False

try:  # pragma: no cover - Windows-only
    import win32gui
    import win32ui

    _WIN32_AVAILABLE = sys.platform == "win32"
except ImportError:
    win32gui = None
    win32ui = None
    _WIN32_AVAILABLE = False

SECTION_ID = "6-1"
DEFAULT_MAX_PER_GROUP = 3

# report의 finding url은 스캐너가 돌던 환경 기준(host.docker.internal 등 컨테이너
# 전용 호스트)이라 사람이 실제로 열어볼 수 있는 주소가 아니다. 실제 접속 가능한
# 서버 주소로 치환해서 "진짜 웹페이지를 캡처한" 사진이 되게 한다.
DEFAULT_PUBLIC_BASE_URL = "http://192.168.0.55"

# 가로 폭은 항상 이 값으로 고정 — 세로 길이는 내용에 맞춰 자연스럽게 늘어난다.
CANVAS_WIDTH = 1280
# 브라우저 창 초기 크기(내비게이션/렌더링용). 창을 캔버스 폭보다 작게 줄이면 OS
# 창은 작아져도 Chrome의 내부 렌더링 캔버스는 그대로 커서(실측: innerHeight가
# 줄어들지 않고 유지됨) 작은 창이 그 안을 들여다보는 "구멍"처럼 동작해 텍스트가
# 줄 경계와 무관하게 잘린다. 그래서 창은 늘 넉넉한 크기로 유지한다.
WINDOW_SIZE = {"width": CANVAS_WIDTH, "height": 480}

_CHROME_STRIP_H = {"win32": 170, "linux": 100, "darwin": 130}
_DEFAULT_CHROME_STRIP_H = 130


def _chrome_strip_height() -> int:
    return _CHROME_STRIP_H.get(sys.platform, _DEFAULT_CHROME_STRIP_H)


def _find_chrome_hwnd(bounds: dict[str, int]) -> int | None:
    """OS 창 목록에서 우리가 띄운 Chrome 창을 찾는다(클래스명 + 정확한 좌표 일치)."""
    target_rect = (bounds["left"], bounds["top"], bounds["left"] + bounds["width"], bounds["top"] + bounds["height"])
    found: list[int] = []

    def _cb(hwnd: int, _: object) -> bool:
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "Chrome_WidgetWin_1":
            if win32gui.GetWindowRect(hwnd) == target_rect:
                found.append(hwnd)
        return True

    win32gui.EnumWindows(_cb, None)
    return found[0] if found else None


def _print_window_to_png(hwnd: int, dest: Path) -> None:
    """``PrintWindow``(PW_RENDERFULLCONTENT)로 지정한 창 자신에게 직접 그리라고
    요청해서 캡처한다 — 화면상 다른 창이 그 위를 덮고 있어도 상관없다."""
    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    w, h = right - left, bottom - top
    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    save_bitmap = win32ui.CreateBitmap()
    save_bitmap.CreateCompatibleBitmap(mfc_dc, w, h)
    save_dc.SelectObject(save_bitmap)
    try:
        ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)  # PW_RENDERFULLCONTENT
        bmpinfo = save_bitmap.GetInfo()
        bmpstr = save_bitmap.GetBitmapBits(True)
        img = Image.frombuffer("RGB", (bmpinfo["bmWidth"], bmpinfo["bmHeight"]), bmpstr, "raw", "BGRX", 0, 1)
        img.save(dest)
    finally:
        win32gui.DeleteObject(save_bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)


def _capture_chrome_window(bounds: dict[str, int], dest: Path) -> None:
    """실제 Chrome 창의 픽셀을 캡처한다.

    Windows: ``mss``(화면 좌표 기준 캡처)는 다른 창(예: 이 스크립트를 실행 중인
    에디터 창)이 그 화면 영역을 덮고 있으면 그 창을 대신 찍어버린다 — 실측으로
    확인된 실제 버그다. ``PrintWindow``(HWND 지정, PW_RENDERFULLCONTENT)는 화면에
    뭐가 덮여있든 상관없이 창 자신에게 직접 그리라고 요청하므로 이 문제가 없다.

    Linux(Xvfb 등): 우리 프로세스만 쓰는 격리된 가상 디스플레이라 겹칠 다른 창이
    없으므로 ``mss``로도 문제없다(Docker 환경에서 실측 확인됨).
    """
    if _WIN32_AVAILABLE:
        hwnd = _find_chrome_hwnd(bounds)
        if hwnd is not None:
            _print_window_to_png(hwnd, dest)
            return
    with mss.mss() as sct:
        shot = sct.grab(
            {"left": bounds["left"], "top": bounds["top"], "width": bounds["width"], "height": bounds["height"]}
        )
        mss.tools.to_png(shot.rgb, shot.size, output=str(dest))


_PANEL_TOOLBAR_H = 26
_PANEL_COL_HEAD_H = 22

_MODULE_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _MODULE_DIR.parents[2]

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")

# 응답 텍스트 안에서 "정보 노출" 흔적으로 볼 만한 토큰(예외/스택트레이스/시스템 메시지) —
# 실제로 받은 응답 위에 하이라이트만 얹는다. 텍스트 자체는 손대지 않는다.
_LEAK_MARKER_RE = re.compile(
    r"(Exception|Caused by|Traceback|SQLSTATE|systemMessage|stack\s*trace|StackTrace|"
    r"at\s+[\w.$]+\([\w.]+:\d+\)|DEBUG)",
    re.IGNORECASE,
)


def _slug(text: str) -> str:
    return _SLUG_RE.sub("_", text).strip("_")[:80] or "capture"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _highlight(text: str) -> str:
    escaped = html.escape(text or "", quote=False)
    return _LEAK_MARKER_RE.sub(lambda m: f"<mark>{m.group(0)}</mark>", escaped)


# ---------------------------------------------------------------------------
# Report loading — reuse diagnosis/modules/6-1/report_summary.py's aggregation
# instead of re-parsing the multi-million-line raw YAML.
# ---------------------------------------------------------------------------
def _load_report_summary_module():
    diag_module_dir = _BACKEND_ROOT / "diagnosis" / "modules" / "6-1"
    spec = importlib.util.spec_from_file_location(
        "diag_g61_report_summary_ro", diag_module_dir / "report_summary.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load 6-1 report_summary.py from {diag_module_dir}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def default_data_dir() -> Path:
    return _BACKEND_ROOT / "data"


def default_report_path(data_dir: Path | None = None) -> Path:
    return section_report_path(data_dir or default_data_dir(), SECTION_ID)


def _rebuild_summary_from_findings(path: Path, rs: Any) -> dict[str, Any]:
    """Full, correct YAML parse → ``build_g61_summary_from_findings``.

    Deliberately does NOT call ``rs.build_g61_summary_from_yaml`` — that helper
    re-scans the raw YAML text with per-line regexes (``_field()``), which
    truncates any ``body_snippet`` PyYAML wrapped across multiple lines (long
    exception/SQL text almost always is) and can mangle the trailing bytes.
    A real YAML parse has no such limit; ~74k findings / 120MB takes ~25s with
    libyaml's C loader, which is fine for this offline capture tool.
    """
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with path.open(encoding="utf-8") as f:
        raw = yaml.load(f, Loader=loader)
    report = SectionReport.from_dict(raw or {})
    return rs.build_g61_summary_from_findings(report.findings)


def load_summary(report_path: Path | None = None, data_dir: Path | None = None) -> dict[str, Any]:
    """Load (or build+cache) the deduplicated 6-1 finding-group summary."""
    path = report_path or default_report_path(data_dir)
    if not path.is_file():
        raise FileNotFoundError(f"6-1 report not found: {path} (run the 6-1 diagnosis scan first)")
    rs = _load_report_summary_module()
    cached = rs.load_cached_summary(path)
    if cached is not None:
        return cached
    summary = _rebuild_summary_from_findings(path, rs)
    rs.save_summary_cache(path, summary)  # repairs the cache for other readers (e.g. the dashboard) too
    return summary


# ---------------------------------------------------------------------------
# Capture targets
# ---------------------------------------------------------------------------
@dataclass
class CaptureTarget:
    group_key: str
    severity: str
    sk_class: str
    sk_label: str
    rule_id: str
    rule_label: str
    origin: str
    method: str
    url: str
    status_code: str
    snippet: str
    remediation: str
    count: int
    sample_index: int

    @property
    def finding_id(self) -> str:
        return f"{self.group_key}#{self.sample_index}"


def build_capture_targets(
    summary: dict[str, Any],
    *,
    severities: set[str] | None = None,
    max_per_group: int = DEFAULT_MAX_PER_GROUP,
) -> list[CaptureTarget]:
    """Expand summary groups (rule_id-level, already deduped) into per-URL capture targets.

    ``max_per_group`` is the "케이스 별 대표 사진 세트 수" — 3장씩 기본.
    """
    groups = sorted(
        summary.get("groups") or [],
        key=lambda g: (_SEVERITY_ORDER.get(str(g.get("severity")), 9), -int(g.get("count") or 0)),
    )
    targets: list[CaptureTarget] = []
    for g in groups:
        severity = str(g.get("severity") or "info")
        if severities and severity not in severities:
            continue
        urls = list(g.get("sample_urls") or [])[:max_per_group]
        methods = list(g.get("sample_methods") or ["GET"])
        snippets = list(g.get("sample_snippets") or [])
        statuses = list(g.get("top_status_codes") or [])
        for idx, url in enumerate(urls):
            method = methods[idx] if idx < len(methods) else (methods[0] if methods else "GET")
            snippet = snippets[idx] if idx < len(snippets) else (snippets[0] if snippets else "")
            status = statuses[idx] if idx < len(statuses) else (statuses[0] if statuses else "")
            targets.append(
                CaptureTarget(
                    group_key=str(g.get("group_key") or ""),
                    severity=severity,
                    sk_class=str(g.get("sk_class") or ""),
                    sk_label=str(g.get("sk_label") or ""),
                    rule_id=str(g.get("rule_id") or ""),
                    rule_label=str(g.get("rule_label") or g.get("rule_id") or ""),
                    origin=str(g.get("origin") or ""),
                    method=str(method or "GET").upper(),
                    url=str(url),
                    status_code=str(status or ""),
                    snippet=str(snippet)[:2000],
                    remediation=str(g.get("remediation") or ""),
                    count=int(g.get("count") or 0),
                    sample_index=idx,
                )
            )
    return targets


# ---------------------------------------------------------------------------
# Real captured HTTP exchange — every field here comes from an actual
# navigation or an actual live request. Nothing is guessed or reconstructed.
# ---------------------------------------------------------------------------
@dataclass
class RealExchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status: int | None
    response_headers: dict[str, str]
    response_body: str
    note: str = ""  # set when something genuinely failed — never fabricated content


@dataclass
class RealCaptures:
    content_path: Path | None = None  # full real page content (page.screenshot(full_page=True))


def _render_panel_html(
    exch: RealExchange,
    captures: RealCaptures | None,
    verdict: tuple[bool, str] | None = None,
) -> str:
    """본문 전체(선택) + Request/Response 2단 패널 (+ 선택적 판정 배너).

    고정 높이나 overflow 클리핑을 쓰지 않는다 — 세로는 내용에 맞춰 자연스럽게
    늘어나고, 최종 캡처는 ``full_page=True``로 그 전체를 담는다.
    """
    req_lines = [f"{exch.method} {exch.url}", ""]
    req_lines += [f"{k}: {v}" for k, v in exch.request_headers.items()]
    if exch.request_body:
        req_lines += ["", exch.request_body]
    req_text = "\n".join(req_lines)

    if exch.status is not None:
        status_line = f"HTTP/1.1 {exch.status}"
    elif exch.note and "대기" in exch.note:
        status_line = "(응답 대기 중)"
    else:
        status_line = "(요청 실패)"
    resp_lines = [status_line]
    resp_lines += [f"{k}: {v}" for k, v in exch.response_headers.items()]
    resp_lines += ["", exch.response_body or exch.note or "(응답 본문 없음)"]
    resp_text = "\n".join(resp_lines)

    content_html = ""
    if captures and captures.content_path and captures.content_path.is_file():
        with Image.open(captures.content_path) as im:
            content_h = im.height
        content_html = (
            f'<img class="content" src="{captures.content_path.resolve().as_uri()}" '
            f'width="{CANVAS_WIDTH}" height="{content_h}">'
        )

    verdict_html = ""
    if verdict is not None:
        confirmed, reason = verdict
        cls = "verdict-hit" if confirmed else "verdict-miss"
        label = "정보 노출 확인됨 (CONFIRMED)" if confirmed else "정보 노출 미확인"
        verdict_html = (
            f'<div class="verdict {cls}">{html.escape(label)} — {html.escape(reason)}</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<style>
  * {{ box-sizing:border-box; }}
  html, body {{
    margin:0; padding:0; width:{CANVAS_WIDTH}px;
    background:#12151a; font-family:"Segoe UI",Arial,sans-serif;
  }}
  img.content {{ display:block; width:{CANVAS_WIDTH}px; }}
  .verdict {{
    padding:10px 14px; font-size:13px; font-weight:700;
    border-bottom:1px solid #262b33;
  }}
  .verdict-hit {{ background:#3a1414; color:#ff8a80; }}
  .verdict-miss {{ background:#141a14; color:#8bd18b; }}
  .panel {{ width:{CANVAS_WIDTH}px; background:#12151a; color:#e2e6ea; }}
  .toolbar {{
    height:{_PANEL_TOOLBAR_H}px; display:flex; align-items:center; padding:0 12px;
    font-size:11px; color:#8b95a1; background:#1a1e24; border-bottom:1px solid #262b33;
  }}
  .cols {{ display:grid; grid-template-columns:1fr 1fr; }}
  .col {{ border-right:1px solid #262b33; }}
  .col:last-child {{ border-right:none; }}
  .col-head {{
    height:{_PANEL_COL_HEAD_H}px; padding:4px 12px; font-size:10.5px; text-transform:uppercase;
    letter-spacing:.05em; color:#8b95a1; background:#1a1e24;
  }}
  .col pre {{
    margin:0; padding:10px 12px; font-size:12px; line-height:1.5;
    white-space:pre-wrap; word-break:break-word;
    font-family:Consolas,"Courier New",monospace; color:#e2e6ea;
  }}
  mark {{ background:#e0a000; color:#1a1200; padding:0 2px; border-radius:2px; font-weight:700; }}
</style></head>
<body>
  {content_html}
  {verdict_html}
  <div class="panel">
    <div class="toolbar">Request / Response — 실제 캡처된 값</div>
    <div class="cols">
      <div class="col">
        <div class="col-head">Request</div>
        <pre>{_highlight(req_text)}</pre>
      </div>
      <div class="col">
        <div class="col-head">Response</div>
        <pre>{_highlight(resp_text)}</pre>
      </div>
    </div>
  </div>
</body></html>"""


# ---------------------------------------------------------------------------
# Authentication — resolve login credentials into cookies/headers to inject
# into the capture session, so protected targets can be reached. Three methods:
#   "config" — reuse the same test-account credentials and login endpoints the
#              6-1 scanner itself already used (data/test-accounts.json +
#              data/login-endpoints.json + config.yaml's auth: block, via
#              diagnosis.probe_auth) instead of asking for credentials again.
#              This is the recommended default when capturing a report that
#              was produced by an authenticated scan.
#   "api"    — call a JSON login endpoint directly and reuse the returned token
#              as a bearer header on every subsequent request.
#   "form"   — drive a real (headed) browser through the login form and lift
#              the resulting session cookies out of that browser context. Since
#              this reuses Playwright (not Selenium), the cookies already come
#              back in the exact shape ``BrowserContext.add_cookies`` expects —
#              no format translation needed before injecting them later.
# ---------------------------------------------------------------------------
def _load_raw_config() -> dict[str, Any]:
    """config.yaml을 그대로 로드 — diagnosis 스캐너가 로그인할 때 쓰는 것과 동일한 파일.

    ``app.services.login_discovery_service._load_raw_config``와 동일한 규칙(``CONFIG_PATH``
    환경변수 우선, 없으면 backend 루트의 ``config.yaml``)을 따르되, private 헬퍼를 모듈
    경계 너머로 그대로 끌어다 쓰지 않도록 이 모듈 안에 동일한 로직을 둔다.
    """
    import os

    import yaml

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (_BACKEND_ROOT / "config.yaml")
    if config_path.is_file():
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return {}


def get_auth_via_config(
    data_dir: Path,
    *,
    raw_config: dict[str, Any] | None = None,
    account_email: str | None = None,
) -> dict[str, str]:
    """data/test-accounts.json + data/login-endpoints.json + config.yaml의 auth 설정을
    그대로 재사용해 로그인한다 — 6-1 스캐너가 이 report를 만들 때 이미 사용한 것과 동일한
    계정/로그인 방식이므로, 캡처할 때 다시 계정 정보를 입력받을 필요가 없다.

    ``account_email``을 주면 그 계정으로, 없으면 로그인에 성공한 첫 번째 계정을 쓴다.
    """
    from diagnosis.probe_auth import all_account_auths
    from inventory.auth_util import auth_headers as _build_auth_headers

    sessions = all_account_auths(raw_config or _load_raw_config(), data_dir=data_dir)
    if not sessions:
        raise RuntimeError(
            "data/test-accounts.json에 로그인 가능한 계정이 없거나 로그인에 실패했습니다 — "
            "--auth-method api/form으로 직접 로그인 정보를 지정하세요."
        )
    session = sessions[0]
    if account_email:
        matched = next((s for s in sessions if s.get("email") == account_email), None)
        if matched is None:
            available = ", ".join(sorted({str(s.get("email")) for s in sessions}))
            raise ValueError(f"'{account_email}' 계정으로 로그인된 세션이 없습니다. 사용 가능한 계정: {available}")
        session = matched

    headers = _build_auth_headers(session)
    if not headers:
        raise RuntimeError(f"'{session.get('email')}' 세션에서 인증 헤더를 만들지 못했습니다.")
    return headers


def get_auth_via_api(
    login_api_url: str, id_field: str, pw_field: str, test_id: str, test_pw: str, token_json_key: str
) -> dict[str, str]:
    """JSON API 로그인 — 토큰을 발급받아 이후 모든 요청에 주입할 헤더로 반환."""
    import requests

    response = requests.post(login_api_url, json={id_field: test_id, pw_field: test_pw}, timeout=10)
    response.raise_for_status()
    body = response.json()
    token = body.get(token_json_key)
    if not token:
        raise ValueError(f"응답 JSON에서 '{token_json_key}' 키를 찾지 못함. 실제 응답 키 목록: {list(body.keys())}")
    return {"Authorization": f"Bearer {token}"}


def get_auth_via_form(
    login_url: str, id_field: str, pw_field: str, test_id: str, test_pw: str, nav_timeout_ms: int = 15000
) -> list[dict[str, Any]]:
    """Form 로그인 — 실제 화면이 있는 브라우저로 로그인 폼을 제출하고 세션 쿠키를 추출."""
    if not _PLAYWRIGHT_AVAILABLE:
        raise RuntimeError("playwright가 설치되어 있지 않습니다. `pip install playwright && playwright install chromium`")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        try:
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.goto(login_url, wait_until="load", timeout=nav_timeout_ms)
            page.fill(f"[name='{id_field}']", test_id)
            page.fill(f"[name='{pw_field}']", test_pw)
            page.click("button[type='submit'], input[type='submit']")
            page.wait_for_timeout(2000)  # 로그인 처리 및 리다이렉트 대기
            return context.cookies()
        finally:
            browser.close()


# ---------------------------------------------------------------------------
# Capture session — real headed browser, real OS-level chrome strip, real
# full-page content, real Request/Response panel built from observed values.
# ---------------------------------------------------------------------------
class G61ScreenshotCapture:
    """6-1 대상마다 [STEP1 공격 전] + [STEP2 입력] + [STEP3 결과] 3장을 캡처한다."""

    def __init__(
        self,
        output_dir: Path,
        *,
        page_wait: float = 1.0,
        nav_timeout_ms: int = 15000,
        raw_config: dict[str, Any] | None = None,
        public_base_url: str | None = None,
        auth_cookies: list[dict[str, Any]] | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> None:
        if not _PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "playwright가 설치되어 있지 않습니다. "
                "`pip install playwright && playwright install chromium`"
            )
        if not _MSS_AVAILABLE:
            raise RuntimeError("mss가 설치되어 있지 않습니다(실제 OS 창 캡처에 필요). `pip install mss`")

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.page_wait = page_wait
        self.nav_timeout_ms = nav_timeout_ms
        self.raw_config = raw_config or {}
        self.public_base = (public_base_url or DEFAULT_PUBLIC_BASE_URL).rstrip("/")
        self.auth_cookies = auth_cookies or []
        self.auth_headers = auth_headers or {}

        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=False,
                args=[
                    "--window-position=0,0",
                    f"--window-size={WINDOW_SIZE['width']},{WINDOW_SIZE['height']}",
                ],
            )
        except Exception as exc:
            self._pw.stop()
            raise RuntimeError(
                "화면이 있는(headed) Chromium을 띄우지 못했습니다 — 진짜 브라우저 창을 "
                "그대로 캡처하려면 접속 가능한 디스플레이가 필요합니다. 물리 모니터가 없는 "
                "환경(Docker/CI)에서는 `xvfb-run -a python screenshot/modules/6-1/run.py`처럼 "
                "가상 디스플레이(Xvfb)로 감싸서 실행하세요."
            ) from exc

        self._context = self._browser.new_context(viewport=None, ignore_https_errors=True)
        if self.auth_headers:
            self._context.set_extra_http_headers(self.auth_headers)
        if self.auth_cookies:
            self._context.add_cookies(self.auth_cookies)
        self.page = self._context.new_page()
        self._cdp = self.page.context.new_cdp_session(self.page)
        self._window_id = self._cdp.send("Browser.getWindowForTarget")["windowId"]
        self._set_window_bounds(WINDOW_SIZE)

    def _set_window_bounds(self, size: dict[str, int]) -> None:
        self._cdp.send(
            "Browser.setWindowBounds",
            {"windowId": self._window_id, "bounds": {"left": 0, "top": 0, **size, "windowState": "normal"}},
        )

    def __enter__(self) -> G61ScreenshotCapture:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._browser.close()
        finally:
            self._pw.stop()

    # ------------------------------------------------------------------
    def capture_all(self, targets: list[CaptureTarget]) -> list[dict[str, Any]]:
        results = [self.capture_target(t) for t in targets]
        manifest = {
            "section_id": SECTION_ID,
            "generated_at": _now_iso(),
            "canvas_width": CANVAS_WIDTH,
            "count": len(results),
            "captures": results,
        }
        (self.output_dir / "manifest.json").write_text(
            json_lib.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return results

    def capture_target(self, target: CaptureTarget) -> dict[str, Any]:
        slug = _slug(f"{target.severity}_{target.rule_id}_{target.sample_index}_{target.origin}")
        before_path = self.output_dir / f"{slug}_1_before.png"
        input_path = self.output_dir / f"{slug}_2_input.png"
        result_path = self.output_dir / f"{slug}_3_result.png"
        nav_url = normalize_url(target.url, public_base_url=self.public_base, raw_config=self.raw_config)

        # STEP1 — 취약 URL을 건드리기 전 정상 오리진 홈 화면
        before_ok = self._capture_before(before_path)

        if target.method == "GET":
            # STEP2(주소창 캡처) + 실제 요청/응답 관측을 한 번에 수행
            exch, captures = self._observe_get(nav_url, input_path)
            mode = "real_navigation"
        else:
            # STEP2 — 아직 응답이 없는, 전송 예정인 요청만 패널로 미리 보여준다
            self._render_pending_request(target, nav_url, input_path)
            exch, captures = self._observe_live_request(target, nav_url), None
            mode = "real_live_request"

        confirmed, reason = self._detect_leak(exch)
        result_ok = self._render_final(exch, result_path, captures, verdict=(confirmed, reason))

        return {
            "finding_id": target.finding_id,
            "group_key": target.group_key,
            "severity": target.severity,
            "sk_class": target.sk_class,
            "rule_id": target.rule_id,
            "rule_label": target.rule_label,
            "origin": target.origin,
            "method": exch.method,
            "url": exch.url,
            "status_code": str(exch.status) if exch.status is not None else target.status_code,
            "count_in_scan": target.count,
            "remediation": target.remediation,
            "capture_mode": mode,
            "confirmed": confirmed,
            "failure_reason": reason,
            "captured": result_ok,
            "error": exch.note or None,
            "before_screenshot": before_path.name if before_ok else None,
            "input_screenshot": input_path.name if input_path.is_file() else None,
            "result_screenshot": result_path.name if result_ok else None,
        }

    # ------------------------------------------------------------------
    def _capture_before(self, dest: Path) -> bool:
        """STEP1 — 취약 URL을 건드리기 전 정상 오리진 홈 화면을 담아 '평소 상태'를 남긴다."""
        try:
            self.page.goto(self.public_base, wait_until="load", timeout=self.nav_timeout_ms)
            time.sleep(self.page_wait)
            self.page.screenshot(path=str(dest), full_page=True)
            return True
        except Exception:  # noqa: BLE001 - before 캡처 실패는 STEP2/3 진행을 막지 않는다
            return False

    def _render_pending_request(self, target: CaptureTarget, nav_url: str, dest: Path) -> bool:
        """STEP2(non-GET) — 브라우저로 재현 불가하므로, 전송 예정인 실제 요청 내용만 보여준다."""
        pending = RealExchange(
            method=target.method,
            url=nav_url,
            request_headers={"Content-Type": "application/json", "Accept": "application/json"},
            request_body="{}",
            status=None,
            response_headers={},
            response_body="",
            note="(응답 대기 중 — STEP3에서 실제 요청을 전송합니다)",
        )
        return self._render_final(pending, dest, None, verdict=None)

    def _detect_leak(self, exch: RealExchange) -> tuple[bool, str]:
        """실제 응답 본문에서 _LEAK_MARKER_RE(예외/스택트레이스 등) 시그니처가
        발견됐는지로 confirmed를 판단한다 — 무리하게 추정하지 않고, 시그니처가 실제로
        보일 때만 confirmed=True로 표시해 오탐을 줄인다."""
        if exch.status is None:
            return False, exch.note or "응답 없음 — 요청 실패"
        body = exch.response_body or ""
        match = _LEAK_MARKER_RE.search(body)
        if match:
            return True, f"응답 본문에서 정보 노출 시그니처 발견: '{match.group(0)}'"
        if exch.status >= 500:
            return True, f"서버 에러 상태 코드 확인: HTTP {exch.status}"
        return False, f"정상 응답 (HTTP {exch.status}) — 정보 노출 시그니처 미발견"

    def _observe_get(self, nav_url: str, input_path: Path) -> tuple[RealExchange, RealCaptures | None]:
        """GET: 실제로 이동해서 진짜 request/response를 관측.

        주소창 스트립은 STEP2(``input_path``)로 바로 저장하고, 본문 전체는
        STEP3 렌더링에 쓰일 임시 파일로 남긴다(``_render_final``이 소비 후 삭제).
        """
        content_path = input_path.with_name(f"{input_path.stem}.content.png")
        try:
            resp = self.page.goto(nav_url, wait_until="load", timeout=self.nav_timeout_ms)
            time.sleep(self.page_wait)
            if resp is None:
                return RealExchange("GET", nav_url, {}, "", None, {}, "", "탐색 실패(응답 없음)"), None

            body = resp.text()[:4000]
            exch = RealExchange(
                method=resp.request.method,
                url=resp.url,
                request_headers=dict(resp.request.headers),
                request_body="",
                status=resp.status,
                response_headers=dict(resp.headers),
                response_body=body,
            )

            # 주소창/탭만 담은 스트립 — 실제 OS 창을 캡처한 뒤 위쪽만 자른다
            # (그 영역엔 본문 텍스트가 없어서 어떻게 잘라도 잘리는 게 없다).
            bounds = self._cdp.send("Browser.getWindowBounds", {"windowId": self._window_id})["bounds"]
            full_path = input_path.with_name(f"{input_path.stem}.full.png")
            _capture_chrome_window(bounds, full_path)
            try:
                img = Image.open(full_path).convert("RGB")
                strip_h = min(_chrome_strip_height(), img.height)
                img.crop((0, 0, img.width, strip_h)).save(input_path)
            finally:
                try:
                    full_path.unlink()
                except OSError:
                    pass

            # 본문 전체 — full_page=True는 뷰포트 높이와 무관하게 실제 콘텐츠 전체를
            # 스크롤/스티칭해서 담으므로 잘리는 부분이 없다.
            self.page.screenshot(path=str(content_path), full_page=True)

            return exch, RealCaptures(content_path=content_path)
        except Exception as exc:  # noqa: BLE001 - report the real reason, keep going
            return RealExchange("GET", nav_url, {}, "", None, {}, "", f"실시간 접속 실패: {str(exc)[:200]}"), None

    def _observe_live_request(self, target: CaptureTarget, nav_url: str) -> RealExchange:
        """POST/PUT/PATCH/DELETE: 브라우저 재현 불가 — finding과 동일한 방식으로 실제 요청."""
        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        req_body = "{}"
        try:
            resp = self._context.request.fetch(
                nav_url,
                method=target.method,
                headers=req_headers,
                data=req_body,
                timeout=self.nav_timeout_ms,
                fail_on_status_code=False,
            )
            try:
                body = resp.text()[:4000]
            except Exception:
                body = "(binary response)"
            return RealExchange(
                method=target.method,
                url=nav_url,
                request_headers=req_headers,
                request_body=req_body,
                status=resp.status,
                response_headers=dict(resp.headers),
                response_body=body,
            )
        except Exception as exc:  # noqa: BLE001 - genuinely could not reach the server; say so
            return RealExchange(
                target.method, nav_url, req_headers, req_body, None, {}, "", f"실시간 요청 실패: {str(exc)[:200]}"
            )

    def _render_final(
        self,
        exch: RealExchange,
        dest: Path,
        captures: RealCaptures | None,
        *,
        verdict: tuple[bool, str] | None,
    ) -> bool:
        tmp_html = dest.with_suffix(".wrapper.html")
        try:
            tmp_html.write_text(_render_panel_html(exch, captures, verdict), encoding="utf-8")
            self.page.set_viewport_size({"width": CANVAS_WIDTH, "height": 200})
            self.page.goto(tmp_html.resolve().as_uri(), wait_until="load", timeout=self.nav_timeout_ms)
            self.page.screenshot(path=str(dest), full_page=True)
            return True
        except Exception:  # noqa: BLE001
            return False
        finally:
            tmp_paths = [tmp_html]
            if captures:
                tmp_paths.append(captures.content_path)
            for tmp in tmp_paths:
                if tmp is None:
                    continue
                try:
                    tmp.unlink()
                except OSError:
                    pass


def _clear_output_dir(out_dir: Path) -> None:
    """이전 실행에서 남은 캡처 결과를 지운다 — 매 실행마다 최신 결과로 덮어써야 하는데,
    report가 바뀌면 finding 슬러그(순서/개수)도 함께 바뀔 수 있어 같은 이름 파일만
    덮어써서는 이전 실행의 낡은 스크린샷이 디렉터리에 계속 섞여 남는다."""
    if not out_dir.is_dir():
        return
    for f in out_dir.glob("*.png"):
        try:
            f.unlink()
        except OSError:
            pass
    manifest = out_dir / "manifest.json"
    if manifest.is_file():
        try:
            manifest.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# End-to-end convenience entry point
# ---------------------------------------------------------------------------
def run_capture(
    *,
    report_path: Path | None = None,
    data_dir: Path | None = None,
    output_dir: Path | None = None,
    severities: set[str] | None = None,
    max_per_group: int = DEFAULT_MAX_PER_GROUP,
    raw_config: dict[str, Any] | None = None,
    public_base_url: str | None = None,
    auth_config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """report 로드 → 캡처 대상 산출 → 스크린샷 캡처까지 한 번에 실행.

    output_dir 기본값은 ``data/report/6-1/evidence/webcapture`` — 다른 진단
    모듈들이 ReplaySession 증거를 저장하는 ``diagnosis.paths.section_evidence_dir``
    관례를 그대로 따른다. ``public_base_url`` 기본값은 ``DEFAULT_PUBLIC_BASE_URL``
    (http://192.168.0.55) — report의 host.docker.internal 주소를 실제 접속 가능한
    주소로 치환할 때 쓴다.

    ``auth_config``: 로그인 필요한 대상을 캡처할 때 사용.

        # 권장: report를 만든 6-1 스캐너가 이미 쓴 계정/로그인 설정을 그대로 재사용
        {"enabled": True, "method": "config", "account_email": "admin@travel.com"}  # account_email 생략 시 첫 계정

        # 직접 로그인 정보를 줄 수도 있음
        {
            "enabled": True,
            "method": "api",  # "api" | "form"
            "login_url": "https://example.com/api/v1/auth/login",
            "id_field": "email",
            "pw_field": "password",
            "test_id": "tester@example.com",
            "test_pw": "Test1234!",
            "token_json_key": "accessToken",  # method == "api"일 때만 필요
        }
    """
    data_dir = data_dir or default_data_dir()
    summary = load_summary(report_path, data_dir)
    targets = build_capture_targets(summary, severities=severities, max_per_group=max_per_group)
    out_dir = output_dir or (section_evidence_dir(data_dir, SECTION_ID) / "webcapture")
    _clear_output_dir(out_dir)

    auth_cookies, auth_headers = None, None
    if auth_config and auth_config.get("enabled"):
        method = auth_config.get("method")
        if method == "config":
            auth_headers = get_auth_via_config(
                data_dir,
                raw_config=raw_config,
                account_email=auth_config.get("account_email"),
            )
        elif method == "api":
            auth_headers = get_auth_via_api(
                login_api_url=auth_config["login_url"],
                id_field=auth_config["id_field"],
                pw_field=auth_config["pw_field"],
                test_id=auth_config["test_id"],
                test_pw=auth_config["test_pw"],
                token_json_key=auth_config.get("token_json_key", "accessToken"),
            )
        elif method == "form":
            auth_cookies = get_auth_via_form(
                login_url=auth_config["login_url"],
                id_field=auth_config["id_field"],
                pw_field=auth_config["pw_field"],
                test_id=auth_config["test_id"],
                test_pw=auth_config["test_pw"],
            )

    with G61ScreenshotCapture(
        out_dir,
        raw_config=raw_config,
        public_base_url=public_base_url,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    ) as cap:
        return cap.capture_all(targets)
