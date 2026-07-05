# =============================================================================
# session_manager.py  ─  Selenium + CDP 세션 관리 모듈
# Chrome WebDriver 로 로그인하고, CDP(Chrome DevTools Protocol)로
# 네트워크 트래픽을 수집합니다.
# =============================================================================

import json
import logging
import re
import threading
import time
from typing import Optional

from selenium import webdriver
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from config import Config

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Selenium WebDriver 를 사용해 로그인하고
    CDP 를 통해 네트워크 트래픽을 수집하는 클래스.

    사용 방법:
        session = SessionManager(cfg)
        session.login(target_url, username, password)
        endpoints = session.get_captured_endpoints()
        cdp_log   = session.get_cdp_network_log()
        session.close()
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.jwt_token: str = ""
        self._cdp_lock = threading.Lock()  # CDP 로그 수집 동시성 보호
        self._cdp_network_log: list = []   # CDP 에서 수집한 네트워크 이벤트
        self._captured_endpoints: list = [] # 발견된 API 경로 목록
        self.driver = None
        self._init_driver()

    # -------------------------------------------------------------------------
    # WebDriver 초기화
    # -------------------------------------------------------------------------
    def _init_driver(self):
        """
        Chrome WebDriver 를 초기화합니다.
        ZAP 프록시를 통과하도록 설정하고, CDP 성능 로그를 활성화합니다.
        """
        options = Options()
        # 백그라운드(Headless) 실행 보장
        options.add_argument("--headless=new")
        # 인증서 오류 무시 (개발 환경)
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        # 안정성 향상 옵션
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        # CDP 네트워크 성능 로그 활성화
        options.set_capability(
            "goog:loggingPrefs", {"performance": "ALL"}
        )
        options.add_experimental_option(
            "perfLoggingPrefs", {"enableNetwork": True, "enablePage": False}
        )

        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=options)
        # 페이지 로딩 타임아웃 강제 (무한 대기 방지)
        self.driver.set_page_load_timeout(15)
        self._enable_cdp_network()
        logger.info("[Session] Chrome WebDriver 초기화 완료")

    def _enable_cdp_network(self):
        """CDP Network 도메인을 활성화합니다. 응답 본문 캡처 버퍼를 100MB 로 설정합니다."""
        self.driver.execute_cdp_cmd(
            "Network.enable",
            {
                "maxTotalBufferSize":   100_000_000,  # 전체 버퍼 100MB
                "maxResourceBufferSize": 50_000_000,  # 개별 리소스 버퍼 50MB
            },
        )

    # -------------------------------------------------------------------------
    # 로그인
    # -------------------------------------------------------------------------
    def login(self, target_url: str, username: str, password: str):
        """
        대상 사이트에 로그인합니다.
        입력 폼이 노출되어 있으면 즉시 기입하고, 숨겨진 모달 형태인 경우
        로그인 유도 버튼(로그인/Login/Sign)을 자동 탐색하여 폼을 연 뒤 로그인을 마칩니다.
        """
        base_url = target_url.rstrip("/")

        for attempt in range(1, self.cfg.LOGIN_MAX_RETRY + 1):
            try:
                logger.info(f"[Session] 로그인 시도 {attempt}/{self.cfg.LOGIN_MAX_RETRY} ─ {base_url}")
                self.driver.get(base_url)
                time.sleep(2.0)

                wait = WebDriverWait(self.driver, self.cfg.SELENIUM_TIMEOUT)

                # 범용 아이디/이메일 입력 필드 셀렉터 (다국어 및 플레이스홀더 대응)
                id_selectors = [
                    "input[name='username']",
                    "input[name='id']",
                    "input[name='email']",
                    "input[type='email']",
                    "input[placeholder*='email' i]",
                    "input[placeholder*='travel' i]",  # Onde 등 특정 플레이스홀더 폴백
                    "input[placeholder*='이메일' i]",
                    "input[placeholder*='아이디' i]",
                    "input[placeholder*='username' i]",
                    "input[type='text']",
                    "#username",
                    "#id",
                ]
                # 범용 패스워드 입력 필드 셀렉터
                pw_selectors = [
                    "input[name='password']",
                    "input[type='password']",
                    "input[placeholder*='password' i]",
                    "input[placeholder*='비밀번호' i]",
                    "#password",
                ]

                # 1) 로그인 폼이 첫 화면에 바로 보이는지 체크
                form_visible = False
                try:
                    # 첫 번째 셀렉터 후보가 뷰포트에 렌더링되어 있는지 확인
                    test_el = self.driver.find_element(By.CSS_SELECTOR, id_selectors[0])
                    if test_el.is_displayed():
                        form_visible = True
                except Exception:
                    pass

                # 2) 폼이 안 보이면, 로그인 유도 버튼(모달 트리거) 클릭 시도
                if not form_visible:
                    trigger_selectors = [
                        "//button[contains(text(), '로그인') or contains(text(), 'Login') or contains(text(), 'Sign')]",
                        "//a[contains(text(), '로그인') or contains(text(), 'Login') or contains(text(), 'Sign')]",
                        "button.login-btn",
                        "a.login-btn",
                        ".btn-login",
                        "button.btn-primary"
                    ]
                    for trigger in trigger_selectors:
                        try:
                            btn = None
                            if trigger.startswith("//"):
                                btn = self.driver.find_element(By.XPATH, trigger)
                            else:
                                btn = self.driver.find_element(By.CSS_SELECTOR, trigger)
                            
                            if btn and btn.is_displayed():
                                logger.info(f"[Session] 로그인 폼 활성화 버튼 클릭 감지: {trigger}")
                                btn.click()
                                time.sleep(1.5)
                                break
                        except Exception:
                            continue

                # 3) 입력 상자 추출 및 기입
                id_field = self._find_element_multi(wait, id_selectors)
                pw_field = self._find_element_multi(wait, pw_selectors)

                id_field.clear()
                id_field.send_keys(username)
                pw_field.clear()
                pw_field.send_keys(password)

                # 4) 범용 제출 버튼 탐색 및 전송 (텍스트 로그인 버튼 우선 매핑)
                submit_selectors = [
                    "//button[contains(text(), '로그인') or contains(text(), 'Login') or contains(text(), 'Sign') or contains(text(), '제출')]",
                    "button.login-btn",
                    ".btn-login",
                    "div.modal button[type='submit']",
                    "button[type='submit']",
                    "input[type='submit']",
                    "form button[type='submit']",
                    "button",
                ]
                submit_btn = self._find_element_multi(wait, submit_selectors)
                
                # 물리 클릭 시도 후 실패 시 Javascript 강제 클릭 폴백
                try:
                    submit_btn.click()
                except Exception as click_err:
                    logger.warning(f"[Session] 일반 클릭 차단됨, Javascript로 강제 클릭 수행: {click_err}")
                    try:
                        self.driver.execute_script("arguments[0].click();", submit_btn)
                    except Exception as js_err:
                        logger.error(f"[Session] JS 클릭 실패: {js_err}")
                        raise click_err

                # 5) 로그인 완료 대기 및 JWT 추출
                time.sleep(5.0)
                self._extract_jwt()

                if self.jwt_token:
                    logger.info(f"[Session] 로그인 성공 ─ JWT 획득 완료")
                else:
                    logger.warning("[Session] 로그인 성공했지만 JWT 를 찾지 못했습니다.")

                # 주요 페이지 크롤링 + CDP 로그 수집
                self._crawl_key_pages(target_url)
                return  # 성공

            except (TimeoutException, NoSuchElementException) as e:
                logger.warning(f"[Session] 로그인 실패 ({attempt}회): {e}")
                if attempt == self.cfg.LOGIN_MAX_RETRY:
                    raise RuntimeError(f"로그인 {self.cfg.LOGIN_MAX_RETRY}회 모두 실패") from e

    def refresh_auth(self) -> bool:
        """
        현재 세션에서 재로그인해 JWT 를 갱신합니다.
        fuzzer.py 가 401/403 임계값 도달 시 호출합니다.

        Returns:
            True: 갱신 성공, False: 실패
        """
        try:
            logger.info("[Session] JWT 갱신 ─ 재로그인 시도...")
            roles = getattr(self.cfg, "ROLE_PASSWORDS", {}) or getattr(self.cfg, "ROLES", {})
            if not roles:
                logger.warning("[Session] JWT refresh skipped: no role credentials configured")
                return False

            username, password = next(iter(roles.items()))
            self.login(
                self.cfg.UI_TARGET_URL or self.cfg.TARGET_URL,
                username,
                password,
            )
            logger.info("[Session] JWT 갱신 성공")
            return True
        except Exception as e:
            logger.error(f"[Session] JWT 갱신 실패: {e}")
            return False

    # -------------------------------------------------------------------------
    # 셀렉터 다중 폴백
    # -------------------------------------------------------------------------
    def _find_element_multi(self, wait: WebDriverWait, selectors: list):
        """
        셀렉터 목록을 순서대로 시도해 처음으로 발견되는 요소를 반환합니다.
        CSS Selector와 XPath(// 시작)를 둘 다 지원하며, 개별 대기는 최대 1.5초로 제한하여 폴백 속도를 올립니다.
        """
        last_exc = None
        # 빠른 폴백을 위한 1.5초 전용 대기기 사용
        quick_wait = WebDriverWait(self.driver, 1.5)
        
        for sel in selectors:
            try:
                by_type = By.XPATH if sel.startswith("//") else By.CSS_SELECTOR
                return quick_wait.until(
                    EC.presence_of_element_located((by_type, sel))
                )
            except (TimeoutException, NoSuchElementException) as e:
                last_exc = e
        raise NoSuchElementException(
            f"다음 셀렉터로 요소를 찾을 수 없습니다: {selectors}"
        ) from last_exc

    # -------------------------------------------------------------------------
    # JWT 추출
    # -------------------------------------------------------------------------
    def _extract_jwt(self):
        """
        로그인 후 브라우저의 localStorage, sessionStorage, 쿠키에서
        JWT 토큰을 찾아 self.jwt_token 에 저장합니다.
        """
        script = """
        // localStorage 에서 JWT 패턴 검색
        for (let i = 0; i < localStorage.length; i++) {
            let key = localStorage.key(i);
            let val = localStorage.getItem(key);
            if (val && (val.startsWith('eyJ') || key.toLowerCase().includes('token'))) {
                return val;
            }
        }
        // sessionStorage 에서 검색
        for (let i = 0; i < sessionStorage.length; i++) {
            let key = sessionStorage.key(i);
            let val = sessionStorage.getItem(key);
            if (val && (val.startsWith('eyJ') || key.toLowerCase().includes('token'))) {
                return val;
            }
        }
        // 쿠키에서 검색
        let cookies = document.cookie.split(';');
        for (let c of cookies) {
            let parts = c.trim().split('=');
            if (parts[0].toLowerCase().includes('token') || (parts[1] && parts[1].startsWith('eyJ'))) {
                return parts[1];
            }
        }
        return null;
        """
        try:
            token = self.driver.execute_script(script)
            if token:
                # "Bearer " 접두어가 있으면 제거
                self.jwt_token = token.replace("Bearer ", "").strip()
        except Exception as e:
            logger.debug(f"[Session] JWT 추출 실패: {e}")

    # -------------------------------------------------------------------------
    # 주요 페이지 크롤링
    # -------------------------------------------------------------------------
    def _crawl_key_pages(self, target_url: str):
        """
        CRAWL_PATHS 에 정의된 경로를 방문하며 CDP 로그를 수집합니다.

        Args:
            target_url: 베이스 URL
        """
        base = target_url.rstrip("/")
        for path in self.cfg.CRAWL_PATHS:
            try:
                self.driver.get(f"{base}{path}")
                time.sleep(1)  # 페이지 로드 대기
                self._collect_cdp_logs()
            except Exception as e:
                logger.debug(f"[Session] 크롤링 실패 ─ {path}: {e}")

        logger.info(f"[Session] CDP 로그 수집 완료 ─ 이벤트 수: {len(self._cdp_network_log)}")

    # -------------------------------------------------------------------------
    # CDP 로그 수집
    # -------------------------------------------------------------------------
    def _collect_cdp_logs(self):
        """
        performance 로그에서 Network.responseReceived 이벤트를 파싱하고
        응답 본문을 CDP getResponseBody 로 가져옵니다.
        """
        try:
            logs = self.driver.get_log("performance")
        except Exception:
            return

        for entry in logs:
            try:
                msg = json.loads(entry.get("message", "{}"))
                params = msg.get("message", {}).get("params", {})
                method = msg.get("message", {}).get("method", "")

                if method != "Network.responseReceived":
                    continue

                response = params.get("response", {})
                url = response.get("url", "")
                status = response.get("status", 0)
                request_id = params.get("requestId", "")
                mime_type = response.get("mimeType", "")

                # API 경로 수집
                if "/api/" in url or url.endswith((".json", ".xml")):
                    path = url.split("?")[0]  # 쿼리스트링 제거
                    from urllib.parse import urlparse
                    parsed_path = urlparse(path).path
                    if parsed_path and parsed_path not in self._captured_endpoints:
                        self._captured_endpoints.append(parsed_path)

                # 응답 본문 가져오기 (JSON 응답만)
                body_text = ""
                body_json = None
                if "json" in mime_type and request_id:
                    try:
                        body_result = self.driver.execute_cdp_cmd(
                            "Network.getResponseBody",
                            {"requestId": request_id},
                        )
                        body_text = body_result.get("body", "")
                        body_json = json.loads(body_text)
                    except Exception:
                        pass

                log_entry = {
                    "url": url,
                    "status": status,
                    "mime_type": mime_type,
                    "request_id": request_id,
                    "response_body_snippet": body_text[:500] if body_text else "",
                    "response_json": body_json,
                    "response_headers": response.get("headers", {}),
                    "encoded_data_length": response.get("encodedDataLength", 0),
                }

                with self._cdp_lock:
                    self._cdp_network_log.append(log_entry)

            except Exception as e:
                logger.debug(f"[Session] CDP 로그 파싱 오류: {e}")

    # -------------------------------------------------------------------------
    # 공개 인터페이스
    # -------------------------------------------------------------------------
    def get_captured_endpoints(self) -> list:
        """Selenium 이 수집한 API 경로 목록을 반환합니다."""
        return list(self._captured_endpoints)

    def get_cdp_network_log(self) -> list:
        """CDP 에서 수집한 전체 네트워크 로그를 반환합니다."""
        with self._cdp_lock:
            return list(self._cdp_network_log)

    def take_screenshot(self, path: str = "screenshot.png"):
        """현재 브라우저 화면을 캡처합니다. (디버깅용)"""
        try:
            self.driver.save_screenshot(path)
            logger.info(f"[Session] 스크린샷 저장: {path}")
        except Exception as e:
            logger.warning(f"[Session] 스크린샷 실패: {e}")

    def close(self):
        """WebDriver 를 안전하게 종료합니다."""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("[Session] Chrome WebDriver 종료 완료")
            except Exception:
                pass
