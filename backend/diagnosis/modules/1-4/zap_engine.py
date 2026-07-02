"""
ARGUS - SSRF / File Inclusion 진단 모듈

OWASP ZAP REST API를 직접 호출하여 다음을 수행합니다:
  1) Context 생성 및 대상 등록
  2) URL List / Swagger 기반 Import (Spider)
  3) SSRF / Path Traversal / Remote File Inclusion에 특화된 Scan Policy 구성
  4) Active Scan 실행 및 진행률 추적
  5) Alert 조회 및 SearchHit 호환 포맷으로 변환

자체 페이로드 인젝터(payload_injector.py)와 결과를 병합할 수 있도록
동일한 출력 스키마(InjectionResult.to_dict()와 호환되는 dict)를 반환합니다.
"""

import time
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import requests

from models import ScanTarget, DetectionSource, VulnType, RiskLevel


# --------------------------------------------------------------------------
# ZAP Alert 이름
# --------------------------------------------------------------------------
ZAP_ALERT_VULN_MAP = {
    "path traversal": VulnType.LFI,
    "remote file inclusion": VulnType.RFI,
    "server side request forgery": VulnType.SSRF,
    "ssrf": VulnType.SSRF,
    "external redirect": VulnType.SSRF,  # Open Redirect도 SSRF 체인의 시작점으로 간주
}

# ZAP risk 문자열 -> 내부 RiskLevel 매핑
ZAP_RISK_MAP = {
    "High": RiskLevel.HIGH,
    "Medium": RiskLevel.MEDIUM,
    "Low": RiskLevel.LOW,
    "Informational": RiskLevel.INFO,
}

# ZAP Active Scanner ID (SSRF/File Inclusion 관련)
# ZAP 2.14+ 기준. 버전에 따라 ID가 다를 수 있으므로 zap_engine 초기화 시 검증 권장.
ZAP_SCANNER_IDS = {
    "PATH_TRAVERSAL": "6",
    "REMOTE_FILE_INCLUSION": "7",
    "SSRF": "40046",          # Cloud Metadata / SSRF 계열 (버전별 차이 있음)
    "EXTERNAL_REDIRECT": "20019",
    "SOURCE_CODE_DISCLOSURE": "42",  # LFI로 인한 소스코드 노출과 연관
}


@dataclass
class ZapAlertResult:
    """ZAP Alert 1건을 ARGUS 표준 포맷으로 정규화한 결과"""
    alert_name: str
    url: str
    method: str
    param: str
    risk_level: RiskLevel
    vuln_type: VulnType
    evidence: str
    attack: str  # ZAP이 실제 주입한 payload
    confirmed: bool = True
    detection_source: DetectionSource = DetectionSource.ZAP_ACTIVE_SCAN

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "param": self.param,
            "vuln_type": self.vuln_type.value,
            "payload": self.attack,
            "confirmed": self.confirmed,
            "evidence": self.evidence,
            "risk_level": self.risk_level.value,
            "detection_method": "ZAP_ACTIVE_SCAN",
            "detection_source": self.detection_source.value,
        }


class ZapEngine:
    """
    ZAP REST API 래퍼. daemon 모드로 실행 중인 ZAP 인스턴스에 연결합니다.

    실행 예시 (Docker):
        docker run -d -p 8090:8090 --network host \\
          ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -port 8090 \\
          -config api.key=argus-secret \\
          -config api.addrs.addr.name=.* -config api.addrs.addr.enabled=true
    """

    def __init__(self, zap_api_url: str = "http://localhost:8090",
                 api_key: str = "", context_name: str = "argus-ssrf-context",
                 timeout: int = 15,
                 auth_headers: Optional[Dict[str, str]] = None):
        self.zap_api_url = zap_api_url.rstrip("/")
        self.api_key = api_key
        self.context_name = context_name
        self.timeout = timeout
        self.context_id: Optional[str] = None
        self.auth_headers = auth_headers or {}

    # ----------------------------------------------------------------
    def _get(self, endpoint: str, params: dict) -> dict:
        params = {**params, "apikey": self.api_key}
        resp = requests.get(f"{self.zap_api_url}{endpoint}",
                             params=params, timeout=self.timeout)
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise requests.HTTPError(
                f"{exc} | ZAP 응답 본문: {resp.text[:500]}",
                response=resp,
                request=resp.request,
            ) from exc
        return resp.json()

    # ----------------------------------------------------------------
    def _candidate_api_urls(self) -> List[str]:
        candidates = [self.zap_api_url]
        if "localhost" in self.zap_api_url:
            candidates.append(self.zap_api_url.replace("localhost", "127.0.0.1"))
        if "127.0.0.1" in self.zap_api_url:
            candidates.append(self.zap_api_url.replace("127.0.0.1", "localhost"))

        candidates.extend([
            "http://127.0.0.1:8090",
            "http://localhost:8090",
        ])

        unique = []
        for url in candidates:
            clean = url.rstrip("/")
            if clean not in unique:
                unique.append(clean)
        return unique

    # ----------------------------------------------------------------
    def health_check(self) -> bool:
        """ZAP daemon이 응답하는지 확인합니다."""
        original_url = self.zap_api_url
        last_error = None

        for candidate in self._candidate_api_urls():
            self.zap_api_url = candidate
            try:
                self._get("/JSON/core/view/version/", {})
                if candidate != original_url:
                    print(f"[ZAP] API endpoint auto-detected: {candidate}")
                return True
            except requests.RequestException as e:
                last_error = e

        self.zap_api_url = original_url
        if last_error:
            print(f"[ZAP connection failed] {last_error}")
        return False

    # ----------------------------------------------------------------
    def configure_auth_headers(self) -> None:
        """Install ZAP Replacer rules that add auth headers to scan traffic."""
        if not self.auth_headers:
            return

        for name, value in self.auth_headers.items():
            description = f"ARGUS auth header: {name}"
            try:
                self._get("/JSON/replacer/action/removeRule/", {"description": description})
            except requests.RequestException:
                pass

            self._get("/JSON/replacer/action/addRule/", {
                "description": description,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": name,
                "replacement": value,
            })

        print(f"[ZAP] Auth header injection configured ({len(self.auth_headers)} header(s))")

    # ----------------------------------------------------------------
    def setup_context(self, base_url: str, scoped_urls: Optional[List[str]] = None) -> str:
        """Create or reuse a Context, then add this scan's target URLs."""
        reused = False
        try:
            existing = self._get("/JSON/context/view/context/", {
                "contextName": self.context_name,
            })
            context = existing.get("context", existing)
            self.context_id = str(context.get("id") or context.get("contextId"))
            if self.context_id == "None":
                raise ValueError("ZAP context response did not contain an id")
            reused = True
        except requests.HTTPError as exc:
            response = exc.response
            status = response.status_code if response is not None else None
            body = (response.text or "").lower() if response is not None else ""
            context_missing = status == 404 or (
                status == 400 and "does_not_exist" in body
            )
            if not context_missing:
                raise
            created = self._get("/JSON/context/action/newContext/", {
                "contextName": self.context_name,
            })
            self.context_id = str(created["contextId"])

        include_urls = scoped_urls or [f"{base_url.rstrip('/')}/*"]
        for url in include_urls:
            if scoped_urls:
                escaped_url = re.escape(url)
                escaped_url = re.sub(r"\\\{[^{}]+\\\}", "[^/?]+", escaped_url)
                regex = f"^{escaped_url}(?:\\?.*)?$"
            else:
                regex = f"^{re.escape(base_url.rstrip('/'))}.*"
            self._get("/JSON/context/action/includeInContext/", {
                "contextName": self.context_name,
                "regex": regex,
            })

        action = "재사용 및 스코프 갱신" if reused else "생성"
        print(f"[ZAP] Context {action} 완료 (id={self.context_id}, target={base_url})")
        return self.context_id

    # ----------------------------------------------------------------
    def import_swagger(self, swagger_url: str, host_override: str = "") -> None:
        """Swagger/OpenAPI 스펙을 ZAP에 Import하여 Site Tree에 등록합니다."""
        if swagger_url.lower().startswith(("http://", "https://")):
            params = {"url": swagger_url}
            if host_override:
                params["hostOverride"] = host_override
            resp = self._get("/JSON/openapi/action/importUrl/", params)
        else:
            absolute_path = str(Path(swagger_url).resolve())
            # ZAP이 Docker에서 실행되면 호스트 경로를 직접 읽을 수 없습니다.
            # 이 파일 경로가 컨테이너에도 보이도록 docker run -v 볼륨 마운트가 필요합니다.
            resp = self._get("/JSON/openapi/action/importFile/", {
                "file": absolute_path,
                "target": host_override or "",
            })
        print(f"[ZAP] Swagger Import 완료: {resp}")
        time.sleep(2)

    # ----------------------------------------------------------------
    def import_urls(self, urls: List[str]) -> None:
        """URL List를 ZAP Site Tree에 직접 등록합니다 (AccessUrl 방식)."""
        for url in urls:
            try:
                self._get("/JSON/core/action/accessUrl/",
                          {"url": url, "followRedirects": "true"})
            except requests.RequestException as e:
                print(f"[ZAP] URL 등록 실패 ({url}): {e}")
        print(f"[ZAP] URL List {len(urls)}건 Site Tree 등록 완료")
        time.sleep(1)

    # ----------------------------------------------------------------
    def spider_scan(self, base_url: str) -> None:
        """전통적인 Spider로 추가 엔드포인트를 탐색합니다 (SPA가 아닌 경우)."""
        resp = self._get("/JSON/spider/action/scan/", {
            "url": base_url,
            "contextId": self.context_id or "",
            "recurse": "true",
        })
        scan_id = resp["scan"]

        while True:
            status = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
            pct = int(status["status"])
            print(f"[ZAP] Spider 진행률: {pct}%")
            if pct >= 100:
                break
            time.sleep(3)

    # ----------------------------------------------------------------
    def configure_ssrf_lfi_policy(self, policy_name: str = "ssrf-lfi-policy") -> None:
        """
        SSRF / File Inclusion에 특화된 Scan Policy를 구성합니다.
        가이드라인 1-4 항목과 직접 관련된 스캐너만 LOW threshold로 활성화하고,
        나머지 스캐너는 비활성화하여 스캔 시간을 단축합니다.
        """
        try:
            self._get("/JSON/ascan/action/addScanPolicy/",
                      {"scanPolicyName": policy_name})
        except requests.RequestException:
            pass  # 이미 존재하는 정책이면 무시

        # 1) 전체 스캐너 비활성화 (집중도 향상)
        self._get("/JSON/ascan/action/disableAllScanners/",
                  {"scanPolicyName": policy_name})

        try:
            scanner_response = self._get("/JSON/ascan/view/scanners/", {
                "scanPolicyName": policy_name,
            })
        except requests.RequestException as exc:
            scanner_response = {"scanners": []}
            print(f"[ZAP] 스캐너 목록 조회 실패 - fallback ID 사용: {exc}")
        dynamic_ssrf_ids = [
            str(scanner["id"]) for scanner in scanner_response.get("scanners", [])
            if scanner.get("id") is not None and any(
                keyword in str(scanner.get("name", "")).lower()
                for keyword in ("ssrf", "server side request forgery")
            )
        ]
        if dynamic_ssrf_ids:
            print(f"[ZAP] SSRF 스캐너 동적 탐색 완료: {dynamic_ssrf_ids}")
        else:
            dynamic_ssrf_ids = [ZAP_SCANNER_IDS["SSRF"]]
            print(f"[ZAP] SSRF 스캐너 이름 탐색 실패 - fallback ID 사용: {dynamic_ssrf_ids[0]}")

        scanner_ids = [
            scanner_id for name, scanner_id in ZAP_SCANNER_IDS.items() if name != "SSRF"
        ] + dynamic_ssrf_ids

        # 2) SSRF/File Inclusion 관련 스캐너만 활성화 + threshold LOW
        for scanner_id in dict.fromkeys(scanner_ids):
            try:
                self._get("/JSON/ascan/action/setScannerAlertThreshold/", {
                    "id": scanner_id,
                    "alertThreshold": "LOW",
                    "scanPolicyName": policy_name,
                })
                self._get("/JSON/ascan/action/setScannerAttackStrength/", {
                    "id": scanner_id,
                    "attackStrength": "HIGH",  # 더 많은 페이로드 변형 시도
                    "scanPolicyName": policy_name,
                })
            except requests.RequestException as e:
                print(f"[ZAP] 스캐너({scanner_id}) 설정 실패 (버전별 ID 차이 가능): {e}")

        print(f"[ZAP] SSRF/File Inclusion 전용 정책 구성 완료: {policy_name}")

    # ----------------------------------------------------------------
    def active_scan(self, base_url: str, scoped_urls: Optional[List[str]] = None,
                     policy_name: str = "ssrf-lfi-policy",
                     poll_interval: int = 5) -> str:
        """Active Scan을 실행하고 완료까지 대기합니다."""
        scan_start_url = scoped_urls[0] if scoped_urls else base_url
        resp = self._get("/JSON/ascan/action/scan/", {
            "url": scan_start_url,
            "contextId": self.context_id or "",
            "scanPolicyName": policy_name,
            "recurse": "true",
            "inScopeOnly": "true",
        })
        scan_id = resp["scan"]
        print(f"[ZAP] Active Scan 시작 (scan_id={scan_id})")

        while True:
            status = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
            pct = int(status["status"])
            print(f"[ZAP] Active Scan 진행률: {pct}%")
            if pct >= 100:
                break
            time.sleep(poll_interval)

        return scan_id

    # ----------------------------------------------------------------
    def get_alerts(self, base_url: str) -> List[ZapAlertResult]:
        """
        Active Scan 완료 후 Alert를 조회하고, SSRF/File Inclusion 관련 항목만
        ARGUS 표준 포맷(ZapAlertResult)으로 변환합니다.
        """
        resp = self._get("/JSON/alert/view/alerts/", {"baseurl": base_url})
        raw_alerts = resp.get("alerts", [])

        results: List[ZapAlertResult] = []
        for alert in raw_alerts:
            alert_name_lower = alert.get("alert", "").lower()

            vuln_type = None
            for keyword, vtype in ZAP_ALERT_VULN_MAP.items():
                if keyword in alert_name_lower:
                    vuln_type = vtype
                    break

            if vuln_type is None:
                continue  # SSRF/File Inclusion과 무관한 Alert는 스킵

            risk_level = ZAP_RISK_MAP.get(alert.get("risk", ""), RiskLevel.LOW)

            results.append(ZapAlertResult(
                alert_name=alert.get("alert", ""),
                url=alert.get("url", ""),
                method=alert.get("method", "GET"),
                param=alert.get("param", ""),
                risk_level=risk_level,
                vuln_type=vuln_type,
                evidence=alert.get("evidence", "") or alert.get("description", "")[:200],
                attack=alert.get("attack", ""),
            ))

        print(f"[ZAP] SSRF/File Inclusion 관련 Alert {len(results)}건 추출 "
              f"(전체 Alert {len(raw_alerts)}건 중)")
        return results

    # ----------------------------------------------------------------
    def run_full_scan(self, base_url: str, swagger_url: str = "",
                       url_list: Optional[List[str]] = None,
                       host_override: str = "",
                       scoped_urls: Optional[List[str]] = None) -> List[ZapAlertResult]:
        """
        Context 생성 -> Import -> Spider -> Active Scan -> Alert 조회까지
        한 번에 실행하는 편의 메서드입니다.
        """
        if not self.health_check():
            raise ConnectionError(
                f"ZAP({self.zap_api_url})에 연결할 수 없습니다. "
                f"daemon이 실행 중인지, api.key가 올바른지 확인하세요."
            )

        self.configure_auth_headers()
        self.setup_context(base_url, scoped_urls=scoped_urls)

        if swagger_url:
            self.import_swagger(swagger_url, host_override=host_override)
        if url_list:
            self.import_urls(url_list)

        self.spider_scan(base_url)
        self.configure_ssrf_lfi_policy()
        self.active_scan(base_url, scoped_urls=scoped_urls)

        return self.get_alerts(base_url)
