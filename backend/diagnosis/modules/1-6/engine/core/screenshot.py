# =============================================================================
# core/screenshot.py
# 취약점 재현 및 Playwright 자동 스크린샷 캡처 모듈
#
# - 해상도: 1280x720 (리사이즈 없이 브라우저 뷰포트 그대로 저장)
# - 모든 캡처 상단에 가짜 브라우저 주소창을 합성하여 캡처 당시의 URL을 노출
# - query/url 공격은 실제 페이지를 재방문해서 캡처하고,
#   body/header/cookie 처럼 브라우저로 재현이 안 되는 공격은 요청/응답 값을
#   보여주는 전용 "증거 사진" HTML을 렌더링해서 캡처
# - PIL 빨간 박스 오버레이(CAP-05)는 나중 단계로 미루고 기본 비활성화
#   (apply_overlay=True로 켤 수 있음)
#
# C팀 인터페이스 필드:
#   image_url, capture_type (SCREENSHOT|REPRODUCTION), resolution (1280x720),
#   overlay_applied (bool)
#
# Playwright는 자체 Chromium 바이너리를 번들하므로 Selenium/시스템 Chrome이
# 없는 슬림 Docker 이미지에서도 동작합니다 (Dockerfile에서
# `playwright install chromium` 필요).
#
# ⚠ 반드시 허가된 테스트 환경(개발/스테이징 서버)에서만 실행하세요. 운영 서버 실행 금지.
# =============================================================================

import html
import json as json_lib
import os
import re
import time
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, urljoin

logger = logging.getLogger(__name__)

# 브라우저 뷰포트 == 최종 출력 해상도 (리사이즈 없음)
BROWSER_WIDTH  = 1280
BROWSER_HEIGHT = 720

OUTPUT_WIDTH   = BROWSER_WIDTH
OUTPUT_HEIGHT  = BROWSER_HEIGHT
RESOLUTION_TAG = f"{OUTPUT_WIDTH}x{OUTPUT_HEIGHT}"

# 케이스(취약점 유형)당 대표 사진 세트 수
DEFAULT_MAX_PER_TYPE = 3

# GET 재현 가능한 취약점 유형 (kisa_code 또는 owasp_id 또는 cwe_id 기반)
GET_REPRODUCIBLE_KISA = {
    "XS",   # XSS 반사
    "SI",   # SQL 인젝션 (에러 페이지)
    "DI",   # 디렉터리 인덱싱
    "AE",   # 관리자 페이지
    "IL",   # 정보 노출
    "PT",   # 경로 탐색
    "FD",   # 파일 다운로드
    "BO",   # 버퍼 오버플로우 (에러 응답)
}

GET_REPRODUCIBLE_OWASP = {
    "A01:2021",  # Broken Access Control
    "A02:2021",  # Cryptographic Failures
    "A05:2021",  # Security Misconfiguration
    "A10:2021",  # SSRF
}

GET_REPRODUCIBLE_CWE = {
    "CWE-200", "CWE-209",  # 정보 노출
    "CWE-22", "CWE-23", "CWE-36",  # 경로 탐색
    "CWE-79", "CWE-80", "CWE-87",  # XSS (반사형)
    "CWE-89",  # SQL (에러 페이지)
    "CWE-601", # 오픈 리다이렉트
    "CWE-306", "CWE-862",  # 인증 우회
}

# 브라우저로 직접 재현 가능한 벡터 (나머지는 요청/응답 증거 사진으로 대체)
NAVIGABLE_VECTORS = ("url", "query", "path")

# 스크린샷 파일명에 금지된 문자
_SAFE_RE = re.compile(r"[^a-zA-Z0-9가-힣_\-]")

# 페이로드 흔적 탐지용 (URL/바디 안에서 공격 구문으로 보이는 부분을 찾아 하이라이트)
_MARKER_RE = re.compile(
    r"('[^']{0,40}'|\"[^\"]{0,40}\"|OR\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?"
    r"|\.\./+[^\s\"'<>]{0,60}|<script[\s\S]{0,80}?</script>|<[^>]{1,60}on\w+\s*=)",
    re.IGNORECASE,
)

# PIL 오버레이 설정 (CAP-05, 기본 비활성)
_OVERLAY_BOX_COLOR   = (220, 0, 0)   # 빨간색 (RGB)
_OVERLAY_BOX_WIDTH   = 3             # 선 굵기 (px)
_OVERLAY_TEXT_COLOR  = (255, 255, 255)
_OVERLAY_BG_COLOR    = (220, 0, 0, 200)  # 반투명 빨간 배경 (RGBA)
_OVERLAY_FONT_SIZE   = 14

# PIL 사용 가능 여부 체크
try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False
    logger.warning("[Screenshot] Pillow 미설치 ─ PIL 오버레이 기능 비활성화. "
                   "설치: pip install Pillow")

# Playwright 사용 가능 여부 체크 (지연 임포트: 브라우저 바이너리가 없는 환경에서도
# 이 모듈 자체는 문제 없이 로드되어야 함)
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_IMPORTABLE = True
except ImportError:
    sync_playwright = None
    _PLAYWRIGHT_IMPORTABLE = False
    logger.warning("[Screenshot] playwright 미설치 ─ 스크린샷 캡처 비활성화. "
                   "설치: pip install playwright && playwright install chromium")


# JS 텍스트 하이라이트 스크립트 (Playwright page.evaluate용 함수 표현식)
_OUTLINE_JS_FN = """
(targetText) => {
    targetText = (targetText || '').trim();
    if (!targetText) return false;
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    var found = false;
    while (walker.nextNode()) {
        var node = walker.currentNode;
        if (node.nodeValue.includes(targetText)) {
            var parent = node.parentElement;
            if (parent && parent.tagName !== 'SCRIPT' && parent.tagName !== 'STYLE') {
                parent.style.outline = '3px solid red';
                parent.style.outlineOffset = '2px';
                found = true;
            }
        }
    }
    return found;
}
"""



def _highlight_marker(text: str, marker: str) -> str:
    """텍스트를 escape하고, marker 부분이 포함돼 있으면 <mark>로 강조."""
    if not text:
        return ""
    escaped = html.escape(text)
    marker = (marker or "").strip()
    if marker:
        escaped_marker = html.escape(marker)
        if escaped_marker and escaped_marker in escaped:
            escaped = escaped.replace(
                escaped_marker,
                f'<mark style="background:#ffe082;border:2px solid #d32f2f;'
                f'padding:1px 3px;border-radius:2px;">{escaped_marker}</mark>',
            )
    return escaped


class ScreenshotCapture:
    """
    Playwright(Chromium)를 이용한 취약점 재현 스크린샷 캡처.

    - 1280x720 고정 해상도, 리사이즈 없음.
    - 캡처 상단에 가짜 브라우저 주소창을 합성해 캡처 당시 URL을 노출.
    - query/url 공격은 실제 페이지 재방문, body/header/cookie 공격은
      요청/응답 값을 보여주는 전용 증거 사진(HTML 렌더 후 캡처)으로 대체.
    - Selenium 기반 SessionManager(Step 3)와 독립적으로 자체 Chromium 세션을
      띄우므로, Step 3(로그인/CDP 캡처)가 skip_selenium으로 꺼져 있어도 동작함.

    Parameters
    ----------
    output_dir    : 스크린샷 저장 디렉터리 (기본: output/screenshots)
    page_wait     : 페이지 로드 후 대기 시간 (초, 기본: 2.0)
    max_per_type  : 취약점 유형(케이스)당 대표 사진 세트 수 (기본: 3)
    apply_overlay : PIL 빨간 박스 오버레이 적용 여부 (기본: False, 나중에 활성화 예정)
    """

    def __init__(self, output_dir: str = "output/screenshots",
                 page_wait: float = 2.0, max_per_type: int = DEFAULT_MAX_PER_TYPE,
                 apply_overlay: bool = False):
        self.output_dir    = output_dir
        self.page_wait     = page_wait
        self.max_per_type  = max_per_type
        self.apply_overlay = apply_overlay and _PIL_AVAILABLE
        os.makedirs(output_dir, exist_ok=True)

        self.enabled = False
        self._pw = None
        self._browser = None
        self._context = None
        self.page = None

        if not _PLAYWRIGHT_IMPORTABLE:
            return

        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=True)
            self._context = self._browser.new_context(
                viewport={"width": BROWSER_WIDTH, "height": BROWSER_HEIGHT}
            )
            self.page = self._context.new_page()
            self.enabled = True
            logger.info(f"[Screenshot] Chromium 세션 시작 완료: {BROWSER_WIDTH}x{BROWSER_HEIGHT}")
        except Exception as e:
            logger.warning(f"[Screenshot] Playwright Chromium 실행 실패 (브라우저 미설치 가능): {e}")
            self._teardown()

        logger.info(f"[Screenshot] 저장 경로: {os.path.abspath(output_dir)}")
        logger.info(f"[Screenshot] PIL 오버레이: {'활성' if self.apply_overlay else '비활성(나중에 적용 예정)'}")

    def _teardown(self) -> None:
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._context = None
        self.page = None
        self.enabled = False

    def close(self) -> None:
        """브라우저 세션 종료. capture_all 호출 후 반드시 호출할 것."""
        self._teardown()

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    def capture_all(self, findings: list, base_url: str = "") -> list:
        """
        merged_findings에서 재현 가능한 항목을 필터링하고
        각 취약점당 [step1: 전, step2: 후] 순차 캡처를 생성합니다.
        케이스(취약점 유형)당 max_per_type 세트까지만 대표로 캡처합니다.

        Returns:
            Jinja2 보고서 연계용 reproduction_flow 리스트
        """
        if not self.enabled:
            logger.info("[Screenshot] Playwright 비활성 상태 ─ 캡처 스킵")
            return []

        reproducible = self._filter_reproducible(findings)
        logger.info(f"[Screenshot] 재현 가능 항목: {len(reproducible)} / {len(findings)}")

        results = []
        type_counts: dict = {}

        for finding in reproducible:
            vuln_type = self._get_vuln_type(finding)
            count     = type_counts.get(vuln_type, 0)
            if count >= self.max_per_type:
                continue
            type_counts[vuln_type] = count + 1

            # UI 맵핑 주소 생성 (Step 1용)
            ui_url = self._build_url(finding, base_url)
            # 원시 백엔드 API 주소 획득 (Step 2용)
            raw_backend_url = finding.get("url") or ui_url

            result = self._capture_two_steps(finding, ui_url, raw_backend_url, base_url)
            if result:
                results.append(result)

        logger.info(f"[Screenshot] 완료: {len(results)}건의 취약점 순차 캡처 완료 "
                    f"(케이스당 최대 {self.max_per_type}세트)")
        return results

    # ------------------------------------------------------------------
    # 내부 메서드 - 필터링 / URL 구성
    # ------------------------------------------------------------------
    def _get_vuln_type(self, finding: dict) -> str:
        """
        취약점 유형 키를 반환합니다.
        max_per_type 제한에 사용되며, KISA 코드 → OWASP ID → CWE ID 순으로 결정합니다.
        """
        kisa = finding.get("kisa_code", "")
        if kisa:
            return kisa
        owasp = finding.get("owasp_id", "") or finding.get("owasp", "")
        if owasp:
            return owasp
        cwe = finding.get("cwe_id", "") or ""
        if cwe:
            return cwe
        return "UNKNOWN"

    def _filter_reproducible(self, findings: list) -> list:
        """GET 재현 가능한 finding만 추출."""

        out = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            kisa_code = f.get("kisa_code", "")
            owasp_id  = f.get("owasp_id", "") or f.get("owasp", "")
            cwe_id    = f.get("cwe_id", "") or ""
            cwe_list  = f.get("cwe", []) or []
            vector    = f.get("attack_vector", "")

            # GET 재현 가능한 KISA/OWASP/CWE 식별
            if kisa_code in GET_REPRODUCIBLE_KISA:
                out.append(f); continue
            if owasp_id in GET_REPRODUCIBLE_OWASP:
                out.append(f); continue
            if cwe_id in GET_REPRODUCIBLE_CWE:
                out.append(f); continue
            if any(c in GET_REPRODUCIBLE_CWE for c in cwe_list):
                out.append(f); continue
            if vector in ("url", "query", "path"):
                out.append(f)
        return out

    def _map_api_to_ui_url(self, api_url: str, base_url: str) -> str:
        """
        API URL(예: http://localhost:8080/api/v1/reservations/flights)을 분석하여
        프론트엔드 UI의 기능 화면 주소(예: http://localhost:5173/reservations)로 지능적으로 매핑합니다.
        """
        if not api_url:
            return base_url

        try:
            parsed_api = urlparse(api_url)
            path = parsed_api.path

            # /api/v1/ 또는 /api/ 등의 API 접두어 제거
            path_clean = re.sub(r"^/api/(v\d+/)?", "/", path)
            parts = [p for p in path_clean.split("/") if p]

            if not parts:
                return base_url.rstrip("/") + "/"

            # 가장 앞단에 위치한 대표 명사 리소스(예: reservations, products) 추출
            first_resource = parts[0]

            # 쿼리스트링 유지
            query_part = f"?{parsed_api.query}" if parsed_api.query else ""

            # base_url(예: http://localhost:5173)과 결합
            ui_mapped = urljoin(base_url.rstrip("/") + "/", first_resource)
            return ui_mapped + query_part
        except Exception:
            return base_url

    def _build_url(self, finding: dict, base_url: str) -> str:
        """finding에서 재현용 실제 프론트엔드 UI URL 구성."""
        raw_url = finding.get("url") or ""

        # 1. 뼈대가 되는 API 엔드포인트 URL 확인
        if not raw_url:
            endpoint = finding.get("endpoint", "")
            if base_url and endpoint:
                raw_url = urljoin(base_url.rstrip("/"), endpoint)
            else:
                raw_url = base_url

        # 2. 쿼리 파라미터 공격값 주입이 필요한 경우
        if finding.get("attack_vector") == "query" and (finding.get("endpoint") or finding.get("url")):
            target_url = finding.get("url") or finding.get("endpoint", "")
            parsed = urlparse(target_url)
            param = finding.get("param", "q")
            value = finding.get("payload_value", "")
            qs = parse_qs(parsed.query)
            qs[param] = [value]
            new_query = urlencode(qs, doseq=True)
            raw_url = urlunparse(parsed._replace(query=new_query))

        # 3. 최종적으로 API 주소를 실제 브라우저 UI 주소(base_url 포트 5173 기반)로 맵핑 변환
        return self._map_api_to_ui_url(raw_url, base_url)

    # ------------------------------------------------------------------
    # 내부 메서드 - 브라우저 조작
    # ------------------------------------------------------------------
    def _capture_page(
        self,
        nav_url: str,
        dest_path: str,
        outline_texts: Optional[list] = None,
    ) -> bool:
        """
        nav_url(실제 페이지 또는 로컬 evidence HTML)을 1280x720 뷰포트 그대로
        캡처해 dest_path에 저장한다. 가짜 주소창 합성 없이 순수 페이지 스크린샷만
        남긴다 — URL은 evidence 메타데이터/증거 사진 텍스트로 이미 노출됨.

        Returns: outline(빨간 테두리) 적용 여부
        """
        outline_applied = False
        self.page.goto(nav_url, wait_until="load", timeout=30000)
        time.sleep(self.page_wait)

        for text in (outline_texts or []):
            if text and len(str(text)) > 3:
                if self._inject_red_outline_to_text(str(text)):
                    outline_applied = True
                    break

        self.page.screenshot(path=dest_path)
        return outline_applied

    def _inject_red_outline_to_text(self, text: str) -> bool:
        """
        DOM을 검색하여 해당 텍스트를 포함하는 요소에 3px solid red 테두리를 그립니다.
        """
        if not text:
            return False
        try:
            return bool(self.page.evaluate(_OUTLINE_JS_FN, text))
        except Exception as e:
            logger.debug(f"[Screenshot] JS outline 주입 실패: {e}")
            return False

    def _extract_marker(self, finding: dict) -> str:
        """URL/바디 안에서 공격 구문으로 보이는 부분을 찾아 하이라이트 대상으로 반환."""
        req = finding.get("request") or {}
        candidates: list[str] = []
        body = req.get("json")
        if body is None:
            body = req.get("body")
        if isinstance(body, dict):
            candidates.extend(str(v) for v in body.values() if isinstance(v, (str, int, float)))
        elif body:
            candidates.append(str(body))
        candidates.append(str(req.get("url") or finding.get("url") or ""))

        for c in candidates:
            m = _MARKER_RE.search(c)
            if m:
                return m.group(0)
        return str(finding.get("payload_name", ""))

    def _build_evidence_panel_html(self, finding: dict) -> str:
        """
        Burp Repeater 스타일의 Request/Response 2단 패널(HTML 조각).
        실제 raw finding에 담긴 request(method/url/headers/json)와
        response_json/response_text_snippet/status_code를 그대로 사용.
        """
        req = finding.get("request") or {}
        method = str(req.get("method") or finding.get("method") or "GET").upper()
        url = str(req.get("url") or finding.get("url") or "")
        headers: dict[str, Any] = req.get("headers") or {}
        body = req.get("json")
        if body is None:
            body = req.get("body")

        status_code = finding.get("status_code", "")
        resp_json = finding.get("response_json")
        resp_text = finding.get("response_text_snippet", "") or ""

        marker = self._extract_marker(finding)

        badges = []
        if finding.get("kisa_code"):
            badges.append(f"KISA {finding['kisa_code']}")
        cwe = finding.get("cwe_id") or (finding.get("cwe", []) or [""])[0]
        if cwe:
            badges.append(str(cwe))
        if finding.get("owasp_id") or finding.get("owasp"):
            badges.append(str(finding.get("owasp_id") or finding.get("owasp")))
        if finding.get("risk"):
            badges.append(str(finding["risk"]).upper())
        badge_html = "".join(f'<span class="badge">{html.escape(b)}</span>' for b in badges)

        header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
        if isinstance(body, dict):
            body_str = json_lib.dumps(body, ensure_ascii=False, indent=2)
        else:
            body_str = str(body) if body else ""

        req_raw = f"{method} {url}"
        if header_lines:
            req_raw += f"\n{header_lines}"
        if body_str:
            req_raw += f"\n\n{body_str}"

        if isinstance(resp_json, dict):
            resp_raw = json_lib.dumps(resp_json, ensure_ascii=False, indent=2)
        else:
            resp_raw = str(resp_text)
        resp_raw = f"HTTP {status_code or '-'}\n\n{resp_raw}"[:2500]

        req_html = _highlight_marker(req_raw, marker)
        resp_html = _highlight_marker(resp_raw, marker)

        return f"""
<div class="panel">
  <div class="panel-head">ARGUS Evidence &middot; Request / Response</div>
  <div class="badges">{badge_html}</div>
  <div class="cols">
    <div class="col">
      <h3>Request</h3>
      <pre>{req_html}</pre>
    </div>
    <div class="col">
      <h3>Response</h3>
      <pre>{resp_html}</pre>
    </div>
  </div>
</div>"""

    def _build_panel_wrapper_html(self, content_uri: str, panel_html: str) -> str:
        """실제 페이지 스크린샷(위) + Request/Response 패널(아래)을 세로로 쌓는 래퍼."""
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; }}
  html, body {{ margin:0; padding:0; background:#0b0f14; }}
  img.page-shot {{ display:block; width:{BROWSER_WIDTH}px; }}
  .panel {{
    width:{BROWSER_WIDTH}px; padding:20px 26px 26px;
    background:#0f1319; color:#d7dde5;
    font-family:"Malgun Gothic","Segoe UI",Arial,sans-serif;
  }}
  .panel-head {{
    font-size:12.5px; font-weight:700; letter-spacing:.04em; text-transform:uppercase;
    color:#7dd3fc; margin-bottom:12px;
  }}
  .badges {{ margin-bottom:14px; }}
  .badge {{
    display:inline-block; background:#3a1414; color:#fca5a5; border:1px solid #6b2323;
    border-radius:4px; padding:3px 9px; margin-right:6px; font-size:11.5px; font-weight:700;
  }}
  .cols {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  .col h3 {{
    margin:0 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#8593a8;
  }}
  pre {{
    margin:0; background:#04070a; border:1px solid #1f2a37; border-radius:6px;
    padding:12px; font-size:12px; line-height:1.5; white-space:pre-wrap; word-break:break-word;
    font-family:Consolas,monospace; color:#d7dde5; max-height:460px; overflow:auto;
  }}
  mark {{ background:#f59e0b; color:#1a1200; padding:0 2px; border-radius:2px; }}
</style></head>
<body>
  <img class="page-shot" src="{content_uri}">
  {panel_html}
</body></html>"""

    def _capture_with_evidence_panel(
        self,
        nav_url: str,
        dest_path: str,
        finding: dict,
        outline_texts: Optional[list] = None,
    ) -> bool:
        """
        nav_url(실제 온데 페이지)을 1280x720으로 캡처한 뒤, 그 아래에
        실제 Request/Response 값을 보여주는 증거 패널을 이어붙여 하나의
        이미지로 저장한다 (전체 높이는 페이지+패널 크기에 맞춰 늘어남).

        Returns: outline(빨간 테두리) 적용 여부
        """
        outline_applied = False
        self.page.goto(nav_url, wait_until="load", timeout=30000)
        time.sleep(self.page_wait)

        for text in (outline_texts or []):
            if text and len(str(text)) > 3:
                if self._inject_red_outline_to_text(str(text)):
                    outline_applied = True
                    break

        tmp_content_path = dest_path + ".content.png"
        tmp_wrapper_path = dest_path + ".wrapper.html"
        try:
            self.page.screenshot(path=tmp_content_path)

            panel_html = self._build_evidence_panel_html(finding)
            wrapper_html = self._build_panel_wrapper_html(
                Path(tmp_content_path).resolve().as_uri(), panel_html
            )
            with open(tmp_wrapper_path, "w", encoding="utf-8") as f:
                f.write(wrapper_html)

            self.page.goto(Path(tmp_wrapper_path).resolve().as_uri(), wait_until="load", timeout=15000)
            self.page.screenshot(path=dest_path, full_page=True)
        finally:
            for tmp in (tmp_content_path, tmp_wrapper_path):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

        return outline_applied

    def _capture_two_steps(self, finding: dict, ui_url: str, raw_backend_url: str, base_url: str) -> Optional[dict]:
        """
        한 취약점당 [step1: 전(UI 화면), step2: 후(진짜 에러 화면 또는 증거 사진)]의
        순차적 캡처를 수행합니다.
        """
        fid = finding.get("id", "")
        vector = finding.get("attack_vector", "")
        payload_val = finding.get("payload_value", finding.get("payload_name", ""))
        snippet = finding.get("response_text_snippet", "")
        navigable = vector in NAVIGABLE_VECTORS

        # 파일명 프리픽스 정의
        safe_url = _SAFE_RE.sub("_", raw_backend_url)[-40:]
        t = int(time.time() * 1000)

        step1_fname = f"step1_before_{fid}_{safe_url}_{t}.png"
        step2_fname = f"step2_result_{fid}_{safe_url}_{t}.png"

        step1_path = os.path.join(self.output_dir, step1_fname)
        step2_path = os.path.join(self.output_dir, step2_fname)

        steps_metadata = []

        try:
            # ──────────────────────────────────────────────────────────
            # Step 1: 공격 구문 주입 전 정상 웹 사이트 화면 ("전")
            # ──────────────────────────────────────────────────────────
            # 404 도배 방지를 위해, Step 1은 실제 Onde 메인 UI 화면(base_url)으로 접속하여 캡처
            logger.info(f"[Screenshot] Step1 진입 -> 정상 UI 접속: {base_url}")

            if vector in ("query", "url"):
                highlight_msg_1 = "URL/Query 파라미터에 공격 구문 인입 상태 (DOM 하이라이트 처리 전)"
            elif vector == "body":
                highlight_msg_1 = f"API Request Body 페이로드 대입 완료 (전송 전) ─ Payload: {payload_val}"
            else:  # header/cookie
                highlight_msg_1 = f"HTTP Header/Cookie 데이터 임의 조작 완료 ─ Header: {payload_val}"

            self._capture_page(base_url, step1_path)

            if self.apply_overlay and os.path.exists(step1_path):
                label1 = f"[STEP 1: 전] {self._make_overlay_label(finding)} | {highlight_msg_1}"
                step1_path = self._apply_pil_overlay(step1_path, label1)

            steps_metadata.append({
                "step": 1,
                "label": "공격 구문 주입",
                "path": step1_path,
                "highlight": highlight_msg_1
            })

            # ──────────────────────────────────────────────────────────
            # Step 2: 취약점 트리거 및 결과 확인 상태 ("후")
            # 실제 온데 페이지(재현 가능하면 결과 페이지, 아니면 기준 화면) +
            # 그 아래 실제 Request/Response 증거 패널을 항상 함께 캡처.
            # ──────────────────────────────────────────────────────────
            # Playwright는 기본적으로 대화상자(alert/confirm)를 자동으로 닫으므로
            # Selenium과 달리 별도의 해제 처리가 필요 없음.

            if navigable:
                logger.info(f"[Screenshot] Step2 진입 -> 공격 후 결과 페이지 접속: {raw_backend_url}")
                nav_url_step2 = raw_backend_url
                # 1순위: 응답 데이터 스니펫, 2순위: 페이로드 문자열 자체
                outline_texts = [snippet, payload_val]
            else:
                logger.info(f"[Screenshot] Step2 진입 -> 기준 화면 + 증거 패널: {raw_backend_url}")
                nav_url_step2 = base_url
                outline_texts = None

            outline_applied = self._capture_with_evidence_panel(
                nav_url_step2, step2_path, finding, outline_texts=outline_texts,
            )

            if navigable:
                highlight_msg_2 = (
                    "에러 메시지 및 반사 구문 하이라이트 처리 완료 + Request/Response 증거 패널"
                    if outline_applied else "취약점 반사/에러 페이지 응답 확인 + Request/Response 증거 패널"
                )
            else:
                highlight_msg_2 = "브라우저 직접 재현 불가 공격 — 기준 화면 + Request/Response 증거 패널"

            # Step 2 오버레이 배너 적용 (빨간 테두리 배너 합성)
            if self.apply_overlay and os.path.exists(step2_path):
                label2 = f"[STEP 2: 후] {self._make_overlay_label(finding)} | {highlight_msg_2}"
                step2_path = self._apply_pil_overlay(step2_path, label2)

            steps_metadata.append({
                "step": 2,
                "label": "취약점 재현 결과",
                "path": step2_path,
                "highlight": highlight_msg_2
            })

            return {
                "finding_id":      fid,
                "kisa_code":       finding.get("kisa_code", ""),
                "cwe_id":          finding.get("cwe_id", "") or finding.get("cwe", []),
                "owasp_id":        finding.get("owasp_id", "") or finding.get("owasp", ""),
                "url":             raw_backend_url,
                "screenshot_path": step2_path,  # 기본 경로는 최종 결과(step2)로 매핑하여 하위 호환성 유지
                "status":          "captured+overlay" if self.apply_overlay else "captured",

                # C팀 인터페이스 필드 유지
                "capture_type":    "SCREENSHOT" if navigable else "REPRODUCTION",
                "resolution":      RESOLUTION_TAG,
                "overlay_applied": self.apply_overlay,
                "image_url":       "",  # 서버 업로드 연계용

                # 순차적 캡처 디테일 데이터 추가 유지
                "steps":           steps_metadata
            }

        except Exception as e:
            logger.warning(f"[Screenshot] 2단계 순차 캡처 실패 ({raw_backend_url}): {e}")
            return {
                "finding_id":      fid,
                "kisa_code":       finding.get("kisa_code", ""),
                "cwe_id":          finding.get("cwe_id", "") or finding.get("cwe", []),
                "owasp_id":        finding.get("owasp_id", "") or finding.get("owasp", ""),
                "url":             raw_backend_url,
                "screenshot_path": "",
                "status":          f"error: {e}",
                "capture_type":    "SCREENSHOT" if navigable else "REPRODUCTION",
                "resolution":      RESOLUTION_TAG,
                "overlay_applied": False,
                "image_url":       "",
                "steps":           []
            }

    def _apply_pil_overlay(self, img_path: str, label: str) -> str:
        """
        CAP-05: PIL로 이미지에 빨간 박스와 설명 텍스트를 합성. (나중 단계, 기본 비활성)

        - 이미지 하단부에 반투명 빨간 배너 + 텍스트 표시
        - 이미지 전체 테두리에 빨간 박스

        Returns: 저장된 오버레이 이미지 경로 (실패 시 "")
        """
        try:
            img_raw = Image.open(img_path)
            img = img_raw.convert("RGBA")
            if img.size != (OUTPUT_WIDTH, OUTPUT_HEIGHT):
                img = img.resize((OUTPUT_WIDTH, OUTPUT_HEIGHT), Image.Resampling.LANCZOS)
            draw = ImageDraw.Draw(img)

            W, H = img.size

            # 1) 이미지 전체 테두리 빨간 박스
            border = _OVERLAY_BOX_WIDTH
            for i in range(border):
                draw.rectangle(
                    [i, i, W - 1 - i, H - 1 - i],
                    outline=_OVERLAY_BOX_COLOR
                )

            # 2) 하단 반투명 배너 (RGBA 레이어로 합성)
            banner_h = 36
            banner_y = H - banner_h
            banner = Image.new("RGBA", (W, banner_h), _OVERLAY_BG_COLOR)
            img.paste(banner, (0, banner_y), banner)

            # 3) 텍스트 렌더링 (한글 지원 맑은 고딕 / 굴림 순으로 시도)
            font = None
            font_paths = [
                "C:/Windows/Fonts/malgun.ttf",  # 맑은 고딕 (Windows 기본)
                "C:/Windows/Fonts/gulim.ttc",   # 굴림 (Windows 기본)
                "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",  # 리눅스 한글 폰트 (설치 시)
                "arial.ttf"
            ]
            for fp in font_paths:
                try:
                    font = ImageFont.truetype(fp, _OVERLAY_FONT_SIZE)
                    break
                except Exception:
                    continue

            if not font:
                try:
                    font = ImageFont.load_default()
                except Exception:
                    font = None

            text_y = banner_y + (banner_h - _OVERLAY_FONT_SIZE) // 2
            draw_kwargs = dict(xy=(8, text_y), text=label, fill=_OVERLAY_TEXT_COLOR)
            if font:
                draw_kwargs["font"] = font
            draw.text(**draw_kwargs)

            # 4) RGBA → RGB 변환 후 원본 파일 덮어쓰기 (빨간 박스가 있는 최종 버전만 저장)
            result_img = img.convert("RGB")
            result_img.save(img_path)
            return img_path

        except Exception as e:
            logger.warning(f"[Screenshot] PIL 오버레이 실패: {e}")
            return ""

    def _make_overlay_label(self, finding: dict) -> str:
        """오버레이 텍스트 레이블 생성."""
        parts = []
        if finding.get("kisa_code"):
            parts.append(f"KISA:{finding['kisa_code']}")
        cwe = finding.get("cwe_id") or (finding.get("cwe", []) or [""])[0]
        if cwe:
            parts.append(f"CWE:{cwe}")
        owasp = finding.get("owasp_id") or finding.get("owasp", "")
        if owasp:
            parts.append(f"OWASP:{owasp}")
        risk = finding.get("risk", "")
        if risk:
            parts.append(f"Risk:{risk}")
        name = finding.get("vuln_name", finding.get("payload_name", ""))
        if name:
            parts.append(f"| {name[:40]}")
        return "  ".join(parts) if parts else "취약점 탐지됨"

    @staticmethod
    def _safe_filename(finding: dict, url: str) -> str:
        """파일명 안전화."""
        vuln   = (finding.get("kisa_code") or finding.get("cwe_id") or
                  finding.get("owasp_id") or "unknown")
        source = finding.get("source", "unknown")
        urlseg = _SAFE_RE.sub("_", url)[-40:]
        ts     = int(time.time() * 1000)
        return f"{source}_{vuln}_{urlseg}_{ts}.png"
