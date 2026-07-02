# =============================================================================
# core/screenshot.py
# 취약점 재현 및 Selenium 자동 스크린샷 캡처 모듈
#
# CAP-04: 800×450 해상도 통일 (아르고스총집합문서 §CAP-04)
# CAP-05: PIL 기반 빨간 박스 + 텍스트 오버레이 (아르고스총집합문서 §CAP-05)
#
# C팀 인터페이스 필드:
#   image_url, capture_type (SCREENSHOT|REPRODUCTION), resolution (800x450),
#   overlay_applied (bool)
#
# ⚠ 반드시 허가된 테스트 환경(개발/스테이징 서버)에서만 실행하세요. 운영 서버 실행 금지.
# =============================================================================

import os
import re
import time
import logging
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, urljoin

logger = logging.getLogger(__name__)

# CAP-04 해상도 표준
BROWSER_WIDTH  = 1280  # 실제 브라우저 렌더링 해상도 (PC 표준)
BROWSER_HEIGHT = 720

OUTPUT_WIDTH   = 800   # 보고서 최종 출력 규격
OUTPUT_HEIGHT  = 450
RESOLUTION_TAG = f"{OUTPUT_WIDTH}x{OUTPUT_HEIGHT}"

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

# 스크린샷 파일명에 금지된 문자
_SAFE_RE = re.compile(r"[^a-zA-Z0-9가-힣_\-]")

# PIL 오버레이 설정 (CAP-05)
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


class ScreenshotCapture:
    """
    Selenium WebDriver를 이용한 취약점 재현 스크린샷 캡처.

    CAP-04: 캡처 전 브라우저 창 크기를 800×450으로 고정합니다.
    CAP-05: PIL로 취약점 영역에 빨간 박스와 설명 텍스트를 합성합니다.

    Parameters
    ----------
    driver      : Selenium WebDriver (SessionManager.driver)
    output_dir  : 스크린샷 저장 디렉터리 (기본: output/screenshots)
    page_wait   : 페이지 로드 후 대기 시간 (초, 기본: 2.0)
    max_per_type: 취약점 유형당 최대 스크린샷 수 (기본: 5)
    """

    def __init__(self, driver, output_dir: str = "output/screenshots",
                 page_wait: float = 2.0, max_per_type: int = 5):
        self.driver       = driver
        self.output_dir   = output_dir
        self.page_wait    = page_wait
        self.max_per_type = max_per_type
        os.makedirs(output_dir, exist_ok=True)

        # ── CAP-04: 1280x720 해상도 강제 (PC 스케일) ──────────────────────────────────────
        try:
            self.driver.set_window_size(BROWSER_WIDTH, BROWSER_HEIGHT)
            logger.info(f"[Screenshot] 창 크기 설정 완료: {BROWSER_WIDTH}x{BROWSER_HEIGHT}")
        except Exception as e:
            logger.warning(f"[Screenshot] 창 크기 설정 실패: {e}")

        logger.info(f"[Screenshot] 저장 경로: {os.path.abspath(output_dir)}")
        logger.info(f"[Screenshot] PIL 오버레이: {'활성' if _PIL_AVAILABLE else '비활성'} (CAP-05)")

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    def capture_all(self, findings: list, base_url: str = "") -> list:
        """
        merged_findings에서 재현 가능한 항목을 필터링하고
        각 취약점당 [step1: 전, step2: 후] 순차 캡처를 생성합니다.

        Returns:
            Jinja2 보고서 연계용 reproduction_flow 리스트
        """
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

            # CAP-04: 매 캡처 전 창 크기 재확인 (PC 해상도 강제)
            try:
                self.driver.set_window_size(BROWSER_WIDTH, BROWSER_HEIGHT)
            except Exception:
                pass

            # UI 맵핑 주소 생성 (Step 1용)
            ui_url = self._build_url(finding, base_url)
            # 원시 백엔드 API 주소 획득 (Step 2용)
            raw_backend_url = finding.get("url") or ui_url

            result = self._capture_two_steps(finding, ui_url, raw_backend_url, base_url)
            if result:
                results.append(result)

        logger.info(f"[Screenshot] 완료: {len(results)}건의 취약점 순차 캡처 완료")
        return results

    # ------------------------------------------------------------------
    # 내부 메서드
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

    def _inject_red_outline_to_text(self, text: str) -> bool:
        """
        DOM을 검색하여 해당 텍스트를 포함하는 요소에 3px solid red 테두리를 그립니다.
        """
        if not text:
            return False
        js_script = """
        var targetText = arguments[0].trim();
        if (!targetText) return false;
        
        // TreeWalker로 텍스트 노드 순회 검색
        var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        var found = false;
        while(walker.nextNode()) {
            var node = walker.currentNode;
            if(node.nodeValue.includes(targetText)) {
                var parent = node.parentElement;
                if (parent && parent.tagName !== 'SCRIPT' && parent.tagName !== 'STYLE') {
                    parent.style.outline = '3px solid red';
                    parent.style.outlineOffset = '2px';
                    found = true;
                }
            }
        }
        return found;
        """
        try:
            return self.driver.execute_script(js_script, text)
        except Exception as e:
            logger.debug(f"[Screenshot] JS outline 주입 실패: {e}")
            return False

    def _capture_two_steps(self, finding: dict, ui_url: str, raw_backend_url: str, base_url: str) -> Optional[dict]:
        """
        한 취약점당 [step1: 전(UI 화면), step2: 후(진짜 에러 화면)]의 순차적 캡처를 수행합니다.
        """
        fid = finding.get("id", "")
        vector = finding.get("attack_vector", "")
        payload_val = finding.get("payload_value", finding.get("payload_name", ""))
        snippet = finding.get("response_text_snippet", "")

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
            self.driver.get(base_url)
            time.sleep(self.page_wait)

            highlight_msg_1 = "취약점 주입 전 정상 Onde 서비스 UI 화면"

            if vector in ("query", "url"):
                # URL/Query 파라미터는 이미 주입되었으므로 본문 하이라이트 주입 전을 캡처
                self.driver.save_screenshot(step1_path)
                highlight_msg_1 = "URL/Query 파라미터에 공격 구문 인입 상태 (DOM 하이라이트 처리 전)"
            
            elif vector == "body":
                # POST body 폼 입력 흉내 또는 API 구조 설명 배너 씌우기
                self.driver.save_screenshot(step1_path)
                highlight_msg_1 = f"API Request Body 페이로드 대입 완료 (전송 전) ─ Payload: {payload_val}"
            
            else: # header/cookie
                self.driver.save_screenshot(step1_path)
                highlight_msg_1 = f"HTTP Header/Cookie 데이터 임의 조작 완료 ─ Header: {payload_val}"

            # Step 1 오버레이 배너 적용
            if _PIL_AVAILABLE and os.path.exists(step1_path):
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
            # ──────────────────────────────────────────────────────────
            logger.info(f"[Screenshot] Step2 진입 -> 공격 후 결과 페이지 접속: {raw_backend_url}")
            self.driver.get(raw_backend_url)
            time.sleep(self.page_wait)
            
            # XSS 경고창 팝업이 떴으면 해제
            try:
                alert = self.driver.switch_to.alert
                alert.dismiss()
            except Exception:
                pass

            # 공격 반영 부분(텍스트) 탐색 및 빨간색 테두리 CSS 주입
            outline_applied = False
            # 1순위: 응답 데이터 스니펫, 2순위: 페이로드 문자열 자체
            for target_text in [snippet, payload_val]:
                if target_text and len(target_text) > 3: # 너무 짧은 값은 오탐 방지
                    if self._inject_red_outline_to_text(target_text):
                        outline_applied = True
                        break

            self.driver.save_screenshot(step2_path)
            highlight_msg_2 = "에러 메시지 및 반사 구문 하이라이트 처리 완료" if outline_applied else "취약점 반사/에러 페이지 응답 확인"

            # Step 2 오버레이 배너 적용 (빨간 테두리 배너 합성)
            if _PIL_AVAILABLE and os.path.exists(step2_path):
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
                "status":          "captured+overlay" if _PIL_AVAILABLE else "captured",
                
                # C팀 인터페이스 필드 유지
                "capture_type":    "SCREENSHOT",
                "resolution":      RESOLUTION_TAG,
                "overlay_applied": _PIL_AVAILABLE,
                "image_url":       "",  # 서버 업로드 연계용
                
                # 순차적 3단계 캡처 디테일 데이터 추가 유지
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
                "capture_type":    "SCREENSHOT",
                "resolution":      RESOLUTION_TAG,
                "overlay_applied": False,
                "image_url":       "",
                "steps":           []
            }

    def _apply_pil_overlay(self, img_path: str, label: str) -> str:
        """
        CAP-05: PIL로 이미지에 빨간 박스와 설명 텍스트를 합성.

        - 이미지 하단부에 반투명 빨간 배너 + 텍스트 표시
        - 이미지 전체 테두리에 빨간 박스
        - 저장: 원본 파일명에 _overlay 접미사

        Returns: 저장된 오버레이 이미지 경로 (실패 시 "")
        """
        try:
            img_raw = Image.open(img_path)
            # 고품질 Lanczos 필터를 사용하여 800x450 (16:9) 비율로 리사이징
            img = img_raw.resize((OUTPUT_WIDTH, OUTPUT_HEIGHT), Image.Resampling.LANCZOS).convert("RGBA")
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
    def _get_vuln_type(finding: dict) -> str:
        """중복 제한을 위한 취약점 유형 키 반환."""
        return (
            finding.get("kisa_code")
            or finding.get("cwe_id")
            or finding.get("owasp_id")
            or finding.get("vuln_type", "unknown")
        )

    @staticmethod
    def _safe_filename(finding: dict, url: str) -> str:
        """파일명 안전화."""
        vuln   = (finding.get("kisa_code") or finding.get("cwe_id") or
                  finding.get("owasp_id") or "unknown")
        source = finding.get("source", "unknown")
        urlseg = _SAFE_RE.sub("_", url)[-40:]
        ts     = int(time.time() * 1000)
        return f"{source}_{vuln}_{urlseg}_{ts}.png"
