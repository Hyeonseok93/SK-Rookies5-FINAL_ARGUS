"""6-1(오류페이지를 통한 정보 노출 여부) — 진짜 화면 + 진짜 Request/Response 캡처.

diagnosis/modules/6-1 스캐너가 만든 report(``data/report/6-1/latest.yaml`` /
``latest-summary.json``)를 읽어, 대표 finding마다 "실제" 증거 사진 3장(공격 전 /
입력(요청) / 결과)을 만든다.

화면이 보이는 진짜 Chrome 창을 실제 OS 레벨로 캡처한다(``mss``/``PrintWindow``) —
주소창, 탭까지 전부 실제 픽셀이다. 그 창 안에서 실제로 로드된 페이지 위에
Burp Suite 스타일의 어두운 패널(Request/Response)을 DOM에 직접 주입한 뒤 그
상태 그대로 창 전체를 캡처하므로, 패널도 실제 브라우저가 그린 진짜 픽셀이다.
캔버스는 항상 1280x720 고정 크기(``WINDOW_SIZE``)다:

- **STEP1 공격 전(before)**: 취약 URL을 건드리기 전, 정상 오리진 홈 화면을
  오버레이 없이 그대로 캡처해 "평소 상태"를 남긴다.
- **STEP2 입력(input)**: 실제로 전송되는 요청을 보여준다. GET은 화면이 보이는
  진짜 Chrome 창을 실제 URL로 이동시켜(주소창에 그 URL이 그대로 보임) 아직
  판정 전 Request 패널만 오버레이로 얹어 캡처한다. POST/PUT/PATCH/DELETE는
  브라우저로 재현할 수 없으므로 원본 페이지 위에 "응답 대기 중" Request
  패널만 얹는다.
- **STEP3 결과(result)**: 같은 요청에서 실제로 관측한 method, URL, 요청/응답
  헤더, 응답 바디를 있는 그대로(꾸밈 없이) Request/Response 2단 패널로 얹어
  캡처하고, 응답 본문에서 정보 노출 시그니처(예외/스택트레이스 등)가 실제로
  발견됐는지로 판단한 confirmed/failure_reason 배너도 함께 얹는다.

POST/PUT/PATCH/DELETE는 브라우저가 그대로 재현할 수 없다 — ``<form method>``는
GET/POST만 가능하고, 폼은 body를 ``application/x-www-form-urlencoded``로 보내서
실제 finding(``Content-Type: application/json``)과 다른 코드 경로를 타
(실측 결과: CORS 오류로 대체됨) 증거로 부적합하다. 그래서 이 경우는 STEP2에서
대기 중인 요청 내용만 보여주고, STEP3에서 finding을 만든 것과 동일한 방식(같은
method, 같은 Content-Type)으로 살아있는 서버에 실제 요청을 보내고 받은 진짜
Request/Response를 패널에 채운다.

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
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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
    import win32process
    import win32ui

    _WIN32_AVAILABLE = sys.platform == "win32"
    if _WIN32_AVAILABLE:
        # DPI-aware로 설정하지 않으면 이 파이썬 프로세스는 Windows가 가상화한
        # (스케일된) 좌표를 GetWindowRect로 돌려주는데, DPI-aware인 Chrome이
        # 보고하는 CDP 좌표는 실제 물리 픽셀이라 서로 어긋난다(실측: 0.9375배
        # 축소된 값이 나옴) — 그래서 항상 DPI-aware를 켜서 같은 좌표계를 쓰게 한다.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
        except Exception:  # noqa: BLE001
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:  # noqa: BLE001
                pass
except ImportError:
    win32gui = None
    win32process = None
    win32ui = None
    _WIN32_AVAILABLE = False

try:
    import psutil

    _PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when psutil isn't installed
    psutil = None
    _PSUTIL_AVAILABLE = False

SECTION_ID = "6-1"
DEFAULT_MAX_PER_GROUP = 3

# report의 finding url은 스캐너가 돌던 환경 기준(host.docker.internal 등 컨테이너
# 전용 호스트)이라 사람이 실제로 열어볼 수 있는 주소가 아니다. 실제 접속 가능한
# 서버 주소로 치환해서 "진짜 웹페이지를 캡처한" 사진이 되게 한다. 이 값은 특정
# 개발 환경(사설 IP)에 묶여 있으므로 ARGUS_CAPTURE_BASE_URL 환경변수나
# --base-url로 항상 재정의할 수 있게 하고, 코드 내 fallback은 최후 수단으로만 쓴다.
DEFAULT_PUBLIC_BASE_URL = os.environ.get("ARGUS_CAPTURE_BASE_URL", "http://localhost")

# 모든 캡처는 이 크기로 고정된 실제 브라우저 창을 그대로 찍는다.
CANVAS_WIDTH = 1280
CANVAS_HEIGHT = 720
WINDOW_SIZE = {"width": CANVAS_WIDTH, "height": CANVAS_HEIGHT}

# 페이지 이동/오버레이 렌더링이 안정될 때까지 대기하는 시간과 Playwright 네비게이션
# 타임아웃 — 느린 서버·네트워크 환경에서는 --page-wait/--nav-timeout-ms로 조정한다.
DEFAULT_PAGE_WAIT_SECONDS = 1.0
DEFAULT_NAV_TIMEOUT_MS = 15000


def _our_descendant_pids() -> set[int]:
    """현재 파이썬 프로세스에서 뻗어나온 모든 자식 프로세스 PID(우리가 launch한
    Playwright 드라이버 → Chromium까지 포함)."""
    if not _PSUTIL_AVAILABLE:
        return set()
    try:
        me = psutil.Process()
        return {p.pid for p in me.children(recursive=True)} | {me.pid}
    except Exception:  # noqa: BLE001
        return set()


def _find_chrome_hwnd(bounds: dict[str, int]) -> int | None:
    """우리가 launch한 Chromium 창을 찾는다.

    좌표 일치나 "포그라운드 창" 매칭은 이 프로젝트 환경에서 실측으로 신뢰할 수
    없다고 확인됐다 — IDE(Antigravity, Chromium 기반)가 우리 자동화 브라우저와
    똑같은 창 클래스(``Chrome_WidgetWin_1``)에 똑같은 좌표로 겹쳐 뜨기도 하고,
    always-on-top 위젯이 포그라운드를 가로채기도 한다. 대신 창을 소유한 프로세스의
    PID가 우리 파이썬 프로세스의 자손인지로 판별한다 — 이건 클래스/좌표가 같아도
    절대 헷갈리지 않는다.
    """
    our_pids = _our_descendant_pids()
    if our_pids:
        candidates: list[int] = []

        def _cb_pid(hwnd: int, _: object) -> bool:
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "Chrome_WidgetWin_1":
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid in our_pids:
                    candidates.append(hwnd)
            return True

        win32gui.EnumWindows(_cb_pid, None)
        if candidates:
            # 같은 프로세스라도 번역 팝업/권한 알림 같은 작은 보조 창이 별도
            # Chrome_WidgetWin_1으로 같이 잡힐 수 있어(실측 확인됨), 그중 면적이
            # 가장 큰 걸 메인 브라우저 창으로 본다.
            def _area(hwnd: int) -> int:
                left, top, right, bottom = win32gui.GetWindowRect(hwnd)
                return max(0, right - left) * max(0, bottom - top)

            return max(candidates, key=_area)

    # PID 매칭이 실패한 경우(예: psutil 미설치)에만 좌표 일치로 폴백한다.
    target_rect = (bounds["left"], bounds["top"], bounds["left"] + bounds["width"], bounds["top"] + bounds["height"])
    found: list[int] = []

    def _cb_rect(hwnd: int, _: object) -> bool:
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "Chrome_WidgetWin_1":
            if win32gui.GetWindowRect(hwnd) == target_rect:
                found.append(hwnd)
        return True

    win32gui.EnumWindows(_cb_rect, None)
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


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


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


# ---------------------------------------------------------------------------
# Burp Suite 스타일 오버레이 — 실제로 로드된 페이지의 DOM 위에 얹어서, 페이지와
# 함께 그대로(OS 레벨로) 캡처되게 한다. 별도 문서를 새로 만들지 않는다.
# ---------------------------------------------------------------------------
_OVERLAY_CSS = """
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
#argus-evidence-verdict { padding: 6px 12px !important; font-size: 12px !important; font-weight: 700 !important; }
#argus-evidence-verdict.hit { background: #3a1414 !important; color: #ff8a80 !important; }
#argus-evidence-verdict.miss { background: #141a14 !important; color: #8bd18b !important; }
#argus-evidence-panels { display: grid !important; height: calc(100vh - 330px) !important; }
#argus-evidence-panels.two-col { grid-template-columns: 1fr 1fr !important; }
#argus-evidence-panels.one-col { grid-template-columns: 1fr !important; }
.argus-evidence-panel { min-width: 0 !important; border-right: 1px solid #383c41 !important;
  background: #111315 !important; }
.argus-evidence-panel:last-child { border-right: none !important; }
.argus-evidence-heading { height: 30px !important; padding: 8px 11px !important; background: #25282c !important;
  color: #72d68b !important; font-size: 12px !important; font-weight: 700 !important; }
.argus-evidence-pre { height: calc(100vh - 360px) !important; margin: 0 !important; padding: 12px !important;
  overflow: hidden !important; color: #d8dde2 !important; white-space: pre-wrap !important;
  overflow-wrap: anywhere !important; font: 10.5px/1.42 ui-monospace, SFMono-Regular, Menlo, monospace !important; }
.argus-evidence-pre mark { background: #e0a000 !important; color: #1a1200 !important; padding: 0 2px !important;
  border-radius: 2px !important; font-weight: 700 !important; }
"""


def _request_text(exch: RealExchange) -> str:
    lines = [f"{exch.method} {exch.url} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in exch.request_headers.items()]
    if exch.request_body:
        lines += ["", exch.request_body]
    return "\n".join(lines)


def _response_text(exch: RealExchange) -> str:
    if exch.status is not None:
        lines = [f"HTTP/1.1 {exch.status}"]
        lines += [f"{k}: {v}" for k, v in exch.response_headers.items()]
        lines += ["", exch.response_body or "(응답 본문 없음)"]
    else:
        lines = ["(응답 대기 중)"] if not exch.note else [exch.note]
    return "\n".join(lines)


def _overlay_markup(
    exch: RealExchange,
    *,
    finding_id: str,
    request_only: bool = False,
    verdict: tuple[bool, str] | None = None,
) -> str:
    verdict_html = ""
    if verdict is not None:
        confirmed, reason = verdict
        cls = "hit" if confirmed else "miss"
        label = "정보 노출 확인됨 (CONFIRMED)" if confirmed else "정보 노출 미확인"
        verdict_html = f'<div id="argus-evidence-verdict" class="{cls}">{_esc(label)} — {_esc(reason)}</div>'

    if request_only:
        panels_html = f"""
    <div id="argus-evidence-panels" class="one-col">
      <div class="argus-evidence-panel"><div class="argus-evidence-heading">Request (응답 대기 중)</div>
        <pre class="argus-evidence-pre">{_highlight(_request_text(exch))}</pre></div>
    </div>"""
    else:
        panels_html = f"""
    <div id="argus-evidence-panels" class="two-col">
      <div class="argus-evidence-panel"><div class="argus-evidence-heading">Request</div>
        <pre class="argus-evidence-pre">{_highlight(_request_text(exch))}</pre></div>
      <div class="argus-evidence-panel"><div class="argus-evidence-heading">Response</div>
        <pre class="argus-evidence-pre">{_highlight(_response_text(exch))}</pre></div>
    </div>"""

    return f"""
<div id="argus-evidence-bottom">
  <div id="argus-evidence-tabs"><b>Burp Suite Professional</b> Target &nbsp; Proxy &nbsp; Intruder &nbsp; Repeater</div>
  <div id="argus-evidence-target">Target: {_esc(exch.url)} · {_esc(finding_id)}</div>
  {verdict_html}
  {panels_html}
</div>"""


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
    import yaml

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (_BACKEND_ROOT / "config.yaml")
    if config_path.is_file():
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return {}


_SCANNED_ACCOUNT_RE = re.compile(r"authenticated:([\w.+-]+@[\w.-]+):")


def first_scanned_account_email(report_path: Path) -> str | None:
    """report(latest.yaml)의 finding 메시지에 남은 ``authenticated:<email>:login``
    표기에서 6-1 스캐너가 실제로 로그인에 썼던 계정 이메일을 읽어온다.

    7만 건 이상일 수 있는 파일 전체를 YAML로 파싱하지 않고, 첫 매치가 나오는
    즉시 멈추는 스트리밍 텍스트 검색만 한다(메시지 포맷은 스캐너가 항상 앞부분
    findings에 먼저 적어두므로 보통 파일 초반에서 곧장 찾긴다).
    """
    if not report_path.is_file():
        return None
    try:
        with report_path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = _SCANNED_ACCOUNT_RE.search(line)
                if match:
                    return match.group(1)
    except OSError:
        return None
    return None


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

    # refresh=True로 강제 라이브 로그인 — 캐시된 세션은 스캔 당시 발급된 토큰이라
    # 캡처 시점엔 이미 만료돼 있을 수 있다(실측 확인됨: 30분 뒤 만료된 캐시 토큰을
    # 그대로 재사용해 전부 401이 났었음).
    sessions = all_account_auths(raw_config or _load_raw_config(), data_dir=data_dir, refresh=True)
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
    login_url: str,
    id_field: str,
    pw_field: str,
    test_id: str,
    test_pw: str,
    nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
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
# Capture session — real headed browser, real OS-level window capture, Burp
# Suite 스타일 오버레이를 실제 페이지 DOM에 주입한 뒤 그대로 캡처한다.
# ---------------------------------------------------------------------------
class G61ScreenshotCapture:
    """6-1 대상마다 [STEP1 공격 전] + [STEP2 입력] + [STEP3 결과] 3장을 캡처한다."""

    def __init__(
        self,
        output_dir: Path,
        *,
        page_wait: float = DEFAULT_PAGE_WAIT_SECONDS,
        nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
        raw_config: dict[str, Any] | None = None,
        public_base_url: str | None = None,
        frontend_base_url: str | None = None,
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
        # public_base: finding url(host.docker.internal:8080 등)을 실제 접속 가능한
        # API 서버 주소로 치환할 때 쓴다. frontend_base: STEP1(공격 전 홈 화면)과
        # STEP2(non-GET pending) 배경으로 보여줄 실제 프론트엔드 페이지 — API 서버와
        # 포트가 다른 경우(SPA + 별도 백엔드) API 루트는 raw JSON이라 "평소 화면"으로
        # 부적절하므로 따로 지정할 수 있게 분리한다.
        self.public_base = (public_base_url or DEFAULT_PUBLIC_BASE_URL).rstrip("/")
        self.frontend_base = (frontend_base_url or self.public_base).rstrip("/")
        self.auth_cookies = auth_cookies or []
        self.auth_headers = auth_headers or {}

        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=False,
                args=[
                    "--window-position=0,0",
                    f"--window-size={WINDOW_SIZE['width']},{WINDOW_SIZE['height']}",
                    # 한국어 페이지에서 자동으로 뜨는 번역 팝업이 별도 창으로 떠서
                    # 캡처를 가릴 수 있어(실측 확인됨) 아예 끈다.
                    "--disable-features=Translate,TranslateUI",
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
            "canvas_height": CANVAS_HEIGHT,
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

        # STEP1 — 취약 URL을 건드리기 전 정상 오리진 홈 화면(오버레이 없음)
        before_ok = self._capture_before(before_path)

        # 프론트엔드가 /api를 프록시하지 않아(실측 확인됨) 이 URL로 직접 이동해도
        # 실제 요청은 전송되지 않는다 — 그래서 요청 자체는 아래에서 fetch()로
        # 따로 보낸다. 다만 STEP2 배경 화면은 "취약 URL과 같은 경로를 프론트
        # 주소로 그대로 옮긴 화면"으로 실제 이동해본다(호스트만 바꾸고 경로/쿼리는
        # 그대로) — 그 경로가 SPA에도 실제로 존재하면 그 화면이 뜨고, 없으면 SPA
        # 기본 화면(홈)으로 fallback된다.
        mirrored_url = urlunsplit(urlsplit(self.frontend_base)[:2] + urlsplit(nav_url)[2:])
        try:
            self.page.goto(mirrored_url, wait_until="load", timeout=self.nav_timeout_ms)
            time.sleep(self.page_wait)
        except Exception:  # noqa: BLE001 - 그 경로로 못 가면 프론트 홈 화면으로 대체
            try:
                self.page.goto(self.frontend_base, wait_until="load", timeout=self.nav_timeout_ms)
                time.sleep(self.page_wait)
            except Exception:  # noqa: BLE001 - 아래 오버레이/캡처 단계가 실패를 그대로 반영한다
                pass

        req_headers = {"Accept": "application/json"}
        req_body = ""
        if target.method != "GET":
            req_headers["Content-Type"] = "application/json"
            req_body = "{}"

        pending = RealExchange(
            method=target.method,
            url=nav_url,
            request_headers=req_headers,
            request_body=req_body,
            status=None,
            response_headers={},
            response_body="",
            note="(응답 대기 중 — STEP3에서 실제 요청을 전송합니다)",
        )
        input_ok = self._render_overlay_shot(pending, target.finding_id, input_path, request_only=True)

        exch = self._fetch_via_page(target.method, nav_url, req_headers, req_body)
        mode = "real_fetch_in_page"

        confirmed, reason = self._detect_leak(exch)
        result_ok = self._render_overlay_shot(
            exch, target.finding_id, result_path, request_only=False, verdict=(confirmed, reason)
        )

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
            "input_screenshot": input_path.name if input_ok else None,
            "result_screenshot": result_path.name if result_ok else None,
        }

    # ------------------------------------------------------------------
    def _capture_before(self, dest: Path) -> bool:
        """STEP1 — 취약 URL을 건드리기 전 정상 오리진 홈 화면을 담아 '평소 상태'를 남긴다."""
        try:
            self.page.goto(self.frontend_base, wait_until="load", timeout=self.nav_timeout_ms)
            time.sleep(self.page_wait)
            self._shoot_window(dest)
            return True
        except Exception:  # noqa: BLE001 - before 캡처 실패는 STEP2/3 진행을 막지 않는다
            return False

    def _shoot_window(self, dest: Path) -> None:
        """우리가 launch한 Chromium 창(주소창/탭 + 실제 내용 + 우리가 주입한
        오버레이까지 전부)을 실제 OS 레벨로 그대로 캡처한다.

        창은 PID로 식별한다(``_find_chrome_hwnd``) — 클래스명/좌표/포그라운드로
        찾으면 화면에 떠 있는 다른 창(IDE, always-on-top 위젯 등)과 헷갈릴 수
        있다는 게 실측으로 확인됐지만, 우리가 launch한 프로세스의 자손 PID인지는
        절대 헷갈리지 않는다. 캡처 자체(``PrintWindow``)는 지정한 창 하나만
        렌더링하므로, 이렇게 정확한 창만 찾으면 다른 창이 섞일 일이 없다.

        환경에 따라 실제 창 크기가 요청한 값과 정확히 일치하지 않을 수 있어(실측
        확인됨), 마지막에 CANVAS_WIDTH x CANVAS_HEIGHT로 정규화한다.
        """
        bounds = self._cdp.send("Browser.getWindowBounds", {"windowId": self._window_id})["bounds"]
        _capture_chrome_window(bounds, dest)
        with Image.open(dest) as im:
            if im.size != (CANVAS_WIDTH, CANVAS_HEIGHT):
                im.convert("RGB").resize((CANVAS_WIDTH, CANVAS_HEIGHT), Image.LANCZOS).save(dest)

    def _inject_overlay(self, markup: str) -> None:
        last_error: Exception | None = None
        for _ in range(3):
            try:
                self.page.evaluate(
                    """({css, markup}) => {
                      document.getElementById('argus-evidence-root')?.remove();
                      const root = document.createElement('div');
                      root.id = 'argus-evidence-root';
                      const style = document.createElement('style');
                      style.textContent = css;
                      root.appendChild(style);
                      const body = document.createElement('div');
                      body.innerHTML = markup;
                      while (body.firstChild) root.appendChild(body.firstChild);
                      document.documentElement.appendChild(root);
                    }""",
                    {"css": _OVERLAY_CSS, "markup": markup},
                )
                return
            except Exception as exc:  # noqa: BLE001 - retry a few times, then give up
                last_error = exc
                self.page.wait_for_timeout(300)
        raise RuntimeError(f"오버레이 주입 실패: {last_error}")

    def _render_overlay_shot(
        self,
        exch: RealExchange,
        finding_id: str,
        dest: Path,
        *,
        request_only: bool,
        verdict: tuple[bool, str] | None = None,
    ) -> bool:
        """실제로 로드돼 있는 현재 페이지 위에 Burp 스타일 패널을 주입하고 창 전체를 캡처."""
        try:
            markup = _overlay_markup(exch, finding_id=finding_id, request_only=request_only, verdict=verdict)
            self._inject_overlay(markup)
            # DOM은 evaluate()가 끝나는 즉시 갱신되지만 화면 리페인트(컴포지팅)는
            # 비동기라, 바로 캡처하면 이전 오버레이 상태가 찍히는 경쟁 상태가 실측
            # 확인됐다 — 실제로 두 번 그려질 때까지 기다려 리페인트를 보장한다.
            self.page.evaluate(
                "() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))"
            )
            self._shoot_window(dest)
            return True
        except Exception:  # noqa: BLE001
            return False

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

    def _fetch_via_page(
        self, method: str, url: str, headers: dict[str, str], body: str
    ) -> RealExchange:
        """지금 로드돼 있는 실제 프론트 페이지의 JS 컨텍스트 안에서 ``fetch()``로
        요청을 보낸다 — 쿠키/세션이 자동으로 실리고 브라우저의 실제 CORS 정책이
        그대로 적용되므로, 실제 앱이 그 API를 호출하는 것과 동일한 조건이다.
        주소창은 계속 프론트 페이지를 가리키고 있어 화면은 절대 안 바뀐다.
        """
        try:
            result = self.page.evaluate(
                """async ({url, method, headers, body}) => {
                  try {
                    const resp = await fetch(url, {
                      method,
                      headers,
                      body: (method === 'GET' || method === 'HEAD') ? undefined : body,
                      credentials: 'include',
                    });
                    const text = await resp.text();
                    const respHeaders = {};
                    resp.headers.forEach((v, k) => { respHeaders[k] = v; });
                    return { ok: true, status: resp.status, headers: respHeaders, body: text.slice(0, 4000) };
                  } catch (e) {
                    return { ok: false, error: String(e) };
                  }
                }""",
                {"url": url, "method": method, "headers": headers, "body": body},
            )
        except Exception as exc:  # noqa: BLE001 - report the real reason, keep going
            return RealExchange(method, url, headers, body, None, {}, "", f"실시간 요청 실패: {str(exc)[:200]}")

        if not result.get("ok"):
            note = f"실시간 요청 실패: {str(result.get('error'))[:200]}"
            return RealExchange(method, url, headers, body, None, {}, "", note)

        return RealExchange(
            method=method,
            url=url,
            request_headers=headers,
            request_body=body,
            status=int(result["status"]),
            response_headers=dict(result.get("headers") or {}),
            response_body=str(result.get("body") or ""),
        )


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
    frontend_base_url: str | None = None,
    auth_config: dict[str, Any] | None = None,
    page_wait: float = DEFAULT_PAGE_WAIT_SECONDS,
    nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
) -> list[dict[str, Any]]:
    """report 로드 → 캡처 대상 산출 → 스크린샷 캡처까지 한 번에 실행.

    output_dir 기본값은 ``data/report/6-1/evidence/webcapture`` — 다른 진단
    모듈들이 ReplaySession 증거를 저장하는 ``diagnosis.paths.section_evidence_dir``
    관례를 그대로 따른다. ``public_base_url`` 기본값은 ``DEFAULT_PUBLIC_BASE_URL``
    (``ARGUS_CAPTURE_BASE_URL`` 환경변수, 없으면 http://localhost) — report의
    host.docker.internal 주소를 실제 접속 가능한 API 서버 주소로 치환할 때 쓴다.
    ``frontend_base_url``을 생략하면 STEP1(공격 전
    홈 화면)/STEP2(non-GET pending)에도 그 API 서버 주소를 그대로 쓰는데, 프론트
    엔드(SPA)가 API와 다른 포트에서 서비스된다면 그 API 루트는 raw JSON이라
    "평소 화면" 캡처로 부적절하다 — 이때 ``frontend_base_url``로 실제 프론트엔드
    주소(예: http://localhost:5173)를 따로 지정한다.

    ``auth_config``: 로그인 필요한 대상을 캡처할 때 사용. 생략(``None``)하면 report
    (``latest.yaml``)에 남은 ``authenticated:<email>:login`` 표기에서 6-1 스캐너가
    실제로 쓴 계정 이메일을 자동으로 읽어 그 계정으로 로그인한다(``method="config"``
    자동 적용) — 이 자동 로그인은 best-effort라 실패해도(예: 그 계정의 자격
    증명을 test-accounts.json에서 못 찾음) 캡처 자체를 막지 않고 비로그인 상태로
    계속 진행한다. 명시적으로 넘긴 ``auth_config``는 이 자동 감지보다 우선한다.

        # 직접 지정하려면:
        {"enabled": True, "method": "config", "account_email": "admin@travel.com"}

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

        # 명시적으로 자동 로그인을 끄려면:
        {"enabled": False}
    """
    data_dir = data_dir or default_data_dir()
    resolved_report_path = report_path or default_report_path(data_dir)
    summary = load_summary(resolved_report_path, data_dir)
    targets = build_capture_targets(summary, severities=severities, max_per_group=max_per_group)
    out_dir = output_dir or (section_evidence_dir(data_dir, SECTION_ID) / "webcapture")
    _clear_output_dir(out_dir)

    auto_detected = False
    if auth_config is None:
        email = first_scanned_account_email(resolved_report_path)
        if email:
            auth_config = {"enabled": True, "method": "config", "account_email": email}
            auto_detected = True

    auth_cookies, auth_headers = None, None
    if auth_config and auth_config.get("enabled"):
        method = auth_config.get("method")
        if method == "config":
            try:
                auth_headers = get_auth_via_config(
                    data_dir,
                    raw_config=raw_config,
                    account_email=auth_config.get("account_email"),
                )
            except Exception:  # noqa: BLE001 - 자동 감지된 로그인은 실패해도 비로그인으로 계속
                if not auto_detected:
                    raise
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
                nav_timeout_ms=nav_timeout_ms,
            )

    with G61ScreenshotCapture(
        out_dir,
        page_wait=page_wait,
        nav_timeout_ms=nav_timeout_ms,
        raw_config=raw_config,
        public_base_url=public_base_url,
        frontend_base_url=frontend_base_url,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    ) as cap:
        return cap.capture_all(targets)
