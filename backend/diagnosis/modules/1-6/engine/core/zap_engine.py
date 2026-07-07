# =============================================================================
# zap_engine.py  ─  ZAP 연동 모듈 (Spider + Active Scan + JWT 주입)
# OWASP ZAP 을 제어해 Spider(크롤링) → Active Scan(취약점 탐지) 순서로 실행합니다.
# =============================================================================

import json
import time
import logging
from urllib.parse import urlparse, parse_qsl
from zapv2 import ZAPv2
from config import Config

logger = logging.getLogger(__name__)


class ZAPEngine:
    """
    ZAP 을 제어하는 클래스.

    사용 순서:
        1. ZAPEngine(cfg) 로 인스턴스 생성
        2. setup_context(target, token) ─ 컨텍스트·정책·JWT 주입 설정
        3. run_spider(target)           ─ Spider 로 URL 목록 수집 (NEW)
        4. run_active_scan(target)      ─ Active Scan 으로 취약점 탐지
        5. get_alerts(target)           ─ 발견된 경보 목록 조회
    """

    def __init__(self, cfg: Config):
        # ZAP API 클라이언트를 초기화합니다
        self.cfg = cfg
        self.zap = ZAPv2(
            apikey=cfg.ZAP_API_KEY,
            proxies=cfg.PROXIES,
        )
        self.context_id: str = ""
        self._verify_connection()

    # -------------------------------------------------------------------------
    # 연결 확인
    # -------------------------------------------------------------------------
    def _verify_connection(self):
        """ZAP 데몬이 정상적으로 실행 중인지 확인합니다."""
        try:
            version = self.zap.core.version
            logger.info(f"[ZAP] 연결 성공 ─ ZAP 버전: {version}")
        except Exception as e:
            raise ConnectionError(
                f"ZAP 에 연결할 수 없습니다. ZAP 데몬이 실행 중인지 확인하세요.\n"
                f"호스트: {self.cfg.ZAP_HOST}:{self.cfg.ZAP_PORT}\n"
                f"오류: {e}"
            )

    # -------------------------------------------------------------------------
    # 컨텍스트 설정 (컨텍스트 생성 + JWT 주입 + 스캔 정책)
    # -------------------------------------------------------------------------
    def setup_context(self, target: str, token: str):
        """
        ZAP 컨텍스트를 만들고 JWT 를 자동 주입하도록 설정합니다.

        Args:
            target: 진단 대상 URL (예: http://localhost:8080)
            token:  로그인 후 획득한 JWT 문자열
        """
        self._create_context(target)
        self._inject_auth(token)
        self._configure_scan_policy()
        logger.info("[ZAP] 컨텍스트 설정 완료")

    def _create_context(self, target: str):
        """ZAP 컨텍스트를 생성하고 대상 URL 패턴을 등록합니다."""
        # 기존 컨텍스트 정리
        for ctx in self.zap.context.context_list:
            try:
                self.zap.context.remove_context(ctx)
            except Exception:
                pass

        self.context_id = self.zap.context.new_context("ARGUS_W16")
        # 대상 URL 하위 모든 경로를 컨텍스트에 포함
        self.zap.context.include_in_context(
            "ARGUS_W16",
            f"{target}.*",
        )
        logger.info(f"[ZAP] 컨텍스트 생성 완료 (ID: {self.context_id})")

    def _inject_auth(self, token: str):
        """
        Replacer API 를 사용해 모든 ZAP 요청에 JWT 를 자동 삽입합니다.
        기존 Authorization 헤더를 덮어씁니다.
        """
        # 기존 JWT 규칙 제거 후 새로 추가
        try:
            self.zap.replacer.remove_rule(description="ARGUS_JWT")
        except Exception:
            pass

        self.zap.replacer.add_rule(
            description="ARGUS_JWT",
            enabled=True,
            matchtype="REQ_HEADER",        # 요청 헤더를 대상으로
            matchregex=False,
            matchstring="Authorization",   # Authorization 헤더를 찾아서
            replacement=f"Bearer {token}", # JWT 값으로 교체
        )
        logger.info("[ZAP] JWT 자동 주입 규칙 설정 완료")

    def update_auth(self, new_token: str):
        """
        JWT 가 갱신됐을 때 ZAP Replacer 규칙을 새 토큰으로 업데이트합니다.
        fuzzer.py 에서 401/403 감지 후 refresh_auth() 를 호출하면
        main.py 가 이 메서드를 호출합니다.
        """
        self._inject_auth(new_token)
        logger.info("[ZAP] JWT 갱신 ─ Replacer 규칙 업데이트 완료")

    def _configure_scan_policy(self):
        """
        W-1-6 전용 스캔 정책을 생성합니다.
        W-1-6 관련 규칙만 HIGH 강도 / LOW 임계값으로 활성화합니다.
        """
        policy = self.cfg.SCAN_POLICY_NAME
        # 기존 정책 제거
        try:
            self.zap.ascan.remove_scan_policy(scanpolicyname=policy)
        except Exception:
            pass

        self.zap.ascan.add_scan_policy(scanpolicyname=policy)

        # 모든 규칙 비활성화 후 W-1-6 규칙만 켜기
        self.zap.ascan.disable_all_scanners(scanpolicyname=policy)
        for rule_id in self.cfg.W16_RULE_IDS:
            self.zap.ascan.enable_scanners(
                ids=rule_id,
                scanpolicyname=policy,
            )
            self.zap.ascan.set_scanner_alert_threshold(
                id=rule_id,
                alertthreshold="LOW",
                scanpolicyname=policy,
            )
            self.zap.ascan.set_scanner_attack_strength(
                id=rule_id,
                attackstrength="HIGH",
                scanpolicyname=policy,
            )
        logger.info(f"[ZAP] 스캔 정책 '{policy}' 구성 완료 ─ 규칙 수: {len(self.cfg.W16_RULE_IDS)}")

    # -------------------------------------------------------------------------
    # Spider 실행 (NEW)
    # -------------------------------------------------------------------------
    def run_spider(self, target: str) -> list:
        """
        ZAP Spider 를 실행해 대상 사이트의 URL 을 자동 수집합니다.
        Active Scan 전에 반드시 실행해야 더 많은 엔드포인트를 탐지할 수 있습니다.

        Args:
            target: 크롤링 시작 URL

        Returns:
            Spider 가 발견한 URL 목록 (list[str])
        """
        logger.info(f"[ZAP Spider] 시작 ─ 대상: {target}")
        scan_id = self.zap.spider.scan(
            url=target,
            contextname="ARGUS_W16",
            recurse=True,
        )

        timeout = self.cfg.SPIDER_TIMEOUT  # 최대 대기 시간 (초)
        elapsed = 0
        poll_interval = 5  # 5초마다 진행률 확인

        while elapsed < timeout:
            progress = int(self.zap.spider.status(scan_id))
            logger.info(f"[ZAP Spider] 진행률: {progress}%")
            if progress >= 100:
                break
            time.sleep(poll_interval)
            elapsed += poll_interval
        else:
            # 타임아웃 시 강제 중단
            self.zap.spider.stop(scan_id)
            logger.warning(f"[ZAP Spider] 타임아웃({timeout}초) ─ 강제 중단")

        # 수집된 URL 목록 가져오기
        discovered_urls = []
        for result in self.zap.spider.results(scan_id):
            url = result.get("url", "") if isinstance(result, dict) else str(result)
            if url.startswith(target):
                discovered_urls.append(url)
        logger.info(f"[ZAP Spider] 완료 ─ 발견된 URL 수: {len(discovered_urls)}")
        return discovered_urls

    # -------------------------------------------------------------------------
    # Active Scan 실행
    # -------------------------------------------------------------------------
    def run_active_scan(self, target: str) -> str:
        """
        ZAP Active Scan 을 실행합니다.
        run_spider() 실행 후에 호출해야 Spider 가 수집한 URL 도 탐지됩니다.

        Args:
            target: Active Scan 대상 URL

        Returns:
            scan_id (str)
        """
        logger.info(f"[ZAP ActiveScan] 시작 ─ 대상: {target}")
        # Active Scan 요청 간 대기 시간 (밀리초 단위) 적용
        if hasattr(self.cfg, "DELAY_BETWEEN_REQUESTS") and self.cfg.DELAY_BETWEEN_REQUESTS > 0:
            delay_ms = int(self.cfg.DELAY_BETWEEN_REQUESTS * 1000)
            try:
                self.zap.ascan.set_delay_in_ms(delay_in_ms=delay_ms)
                logger.info(f"[ZAP ActiveScan] 요청 간 지연 시간 설정 완료: {delay_ms} ms")
            except Exception as e:
                logger.warning(f"[ZAP ActiveScan] 지연 시간 설정 실패: {e}")

        scan_id = self.zap.ascan.scan(
            url=target,
            recurse=True,
            inscopeonly=True,
            scanpolicyname=self.cfg.SCAN_POLICY_NAME,
            contextid=self.context_id,
        )

        timeout_sec = self.cfg.ACTIVE_SCAN_TIMEOUT_MIN * 60
        elapsed = 0
        poll_interval = 5

        while elapsed < timeout_sec:
            progress = int(self.zap.ascan.status(scan_id))
            logger.info(f"[ZAP ActiveScan] 진행률: {progress}%")
            if progress >= 100:
                break
            time.sleep(poll_interval)
            elapsed += poll_interval
        else:
            self.zap.ascan.stop(scan_id)
            logger.warning(f"[ZAP ActiveScan] 타임아웃({self.cfg.ACTIVE_SCAN_TIMEOUT_MIN}분) ─ 강제 중단")

        logger.info("[ZAP ActiveScan] 완료")
        return scan_id

    # -------------------------------------------------------------------------
    # 경보 조회
    # -------------------------------------------------------------------------
    def get_alerts(self, target: str) -> list:
        """
        ZAP 이 발견한 경보(Alert) 목록을 반환합니다.

        Args:
            target: 경보를 조회할 대상 URL

        Returns:
            경보 딕셔너리 목록
        """
        alerts = self.zap.core.alerts(baseurl=target)
        logger.info(f"[ZAP] 경보 수집 완료 ─ 총 {len(alerts)} 건")
        return alerts

    # -------------------------------------------------------------------------
    # ZAP HTTP history에서 "사람이 실제로 성공시킨" 요청을 뽑아 템플릿화.
    #
    # 판단 기준: 응답 상태코드가 200<=status<400 인 것만 "정상 요청"으로
    # 인정한다. 이 기준은 fuzzer.Config.BASELINE_VALID_STATUS_MIN/MAX와
    # 반드시 동일하게 맞춰야 함 (두 곳이 어긋나면 fuzzer가 baseline_ok로
    # 판단한 값인데 애초에 템플릿으로는 안 만들어지는 모순이 생김).
    # -------------------------------------------------------------------------
    def collect_request_templates(self, target: str, output_path: str = "", limit: int = 500) -> list:
        templates = []
        seen = set()
        try:
            messages = self.zap.core.messages(baseurl=target, start=0, count=limit)
        except TypeError:
            messages = self.zap.core.messages(target, 0, limit)
        except Exception as e:
            logger.warning(f"[ZAP] request template collection failed: {e}")
            messages = []

        for msg in messages or []:
            template = self._message_to_template(msg, target)
            if not template:
                continue
            key = (template["method"], template["path"])
            if key in seen:
                continue
            seen.add(key)
            templates.append(template)

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "schema_version": "1.0",
                            "source": "zap_http_history",
                            "target": target,
                            "valid_status_range": [Config.BASELINE_VALID_STATUS_MIN, Config.BASELINE_VALID_STATUS_MAX],
                            "templates": templates,
                        },
                        f,
                        ensure_ascii=False,
                        indent=2,
                    )
            except Exception as e:
                logger.warning(f"[ZAP] request template write failed: {e}")

        logger.info(f"[ZAP] request templates collected: {len(templates)}")
        return templates

    def _message_to_template(self, msg: dict, target: str):
        try:
            method, url = self._request_line(msg.get("requestHeader", ""))
            if not method or not url or not url.startswith(target):
                return None
            status = self._response_status(msg.get("responseHeader", ""))
            if status is not None and not (Config.BASELINE_VALID_STATUS_MIN <= status < Config.BASELINE_VALID_STATUS_MAX):
                return None

            parsed = urlparse(url)
            headers = self._headers_from_request(msg.get("requestHeader", ""))
            body_text = msg.get("requestBody", "") or ""
            body = self._parse_body(body_text, headers)
            return {
                "method": method.upper(),
                "url": url,
                "path": parsed.path or "/",
                "query": dict(parse_qsl(parsed.query, keep_blank_values=True)),
                "headers": self._safe_headers(headers),
                "body": body,
                "body_text": "" if body is not None else body_text[:4000],
                "status_code": status,
            }
        except Exception:
            return None

    @staticmethod
    def _request_line(header: str):
        first = (header or "").splitlines()[0] if header else ""
        parts = first.split()
        if len(parts) < 2:
            return "", ""
        return parts[0], parts[1]

    @staticmethod
    def _response_status(header: str):
        first = (header or "").splitlines()[0] if header else ""
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return None

    @staticmethod
    def _headers_from_request(header: str) -> dict:
        headers = {}
        for line in (header or "").splitlines()[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        return headers

    @staticmethod
    def _safe_headers(headers: dict) -> dict:
        blocked = {"authorization", "cookie", "host", "content-length"}
        return {k: v for k, v in (headers or {}).items() if k.lower() not in blocked}

    @staticmethod
    def _parse_body(body_text: str, headers: dict):
        if not body_text:
            return None
        content_type = ""
        for k, v in (headers or {}).items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break
        if "application/json" in content_type:
            try:
                return json.loads(body_text)
            except Exception:
                return None
        return None