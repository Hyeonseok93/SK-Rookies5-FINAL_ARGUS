# =============================================================================
# collector.py  ─  취약점 결과 통합 모듈
# ZAP 경보 + 퍼저 결과 + CDP 로그를 하나의 목록으로 합칩니다.
# =============================================================================

import json
import logging
import re
from typing import Optional
from urllib.parse import unquote, urlsplit, urlunsplit

try:
    from config import KISA_TO_CWE_OWASP, OWASP_TOP10_2021
except ImportError:
    KISA_TO_CWE_OWASP = {}
    OWASP_TOP10_2021 = {}

logger = logging.getLogger(__name__)

# 위험도 정렬 순서 (낮을수록 높은 위험)
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ZAP 경보에서 W-1-6 관련 키워드 필터
W16_KEYWORDS = [
    "buffer", "overflow", "format string", "deserialization",
    "large", "payload", "injection", "dos", "denial",
    "memory", "heap", "stack",
]

FU_URL_HINTS = ("upload", "file", "image", "attachment", "document")
INJECTION_MARKERS = (
    "..", "%2f", "etc", "passwd", "'", "\"", "<script", "${", "{{", "}}",
    "null", "undefined", "nan", "infinity", " or ", " and ", "%00",
)


class VulnerabilityCollector:
    """
    ZAP, 퍼저, CDP 세 소스의 결과를 통합하고
    중복을 제거한 뒤 위험도 순으로 정렬합니다.

    사용 방법:
        collector = VulnerabilityCollector(zap=zap_engine, session=session_manager)
        merged = collector.merge(fuzzer_findings)
    """

    def __init__(self, zap=None, session=None):
        """
        Args:
            zap:     ZAPEngine 인스턴스 (None 이면 ZAP 수집 건너뜀)
            session: SessionManager 인스턴스 (CDP 로그 수집용)
        """
        self.zap = zap
        self.session = session

    # -------------------------------------------------------------------------
    # ZAP 경보 수집
    # -------------------------------------------------------------------------
    def collect_zap_alerts(self, target: str) -> list:
        """
        ZAP 이 발견한 경보를 수집하고 W-1-6 관련 항목만 필터링합니다.

        Args:
            target: 경보를 조회할 대상 URL

        Returns:
            W-1-6 관련 경보 딕셔너리 목록
        """
        if self.zap is None:
            return []

        raw_alerts = self.zap.get_alerts(target)
        filtered = []

        for alert in raw_alerts:
            name_lower = alert.get("name", "").lower()
            desc_lower = alert.get("description", "").lower()
            risk = alert.get("risk", "INFO")

            # W-1-6 키워드 또는 High/Critical 위험도인 경우만 포함
            is_w16_related = any(kw in name_lower or kw in desc_lower for kw in W16_KEYWORDS)
            is_high_risk = risk in ("High", "Critical")

            if not (is_w16_related or is_high_risk):
                continue

            # 메시지 상세 정보 가져오기 (요청/응답 본문)
            msg_detail = self._fetch_message_detail(alert.get("messageId", ""))

            # 위험도 통일 (ZAP 표기 → 대문자)
            risk_map = {"Informational": "INFO", "Low": "LOW",
                        "Medium": "MEDIUM", "High": "HIGH", "Critical": "CRITICAL"}
            normalized_risk = risk_map.get(risk, risk.upper())

            entry = {
                "source": "zap",
                "url": alert.get("url", ""),
                "vuln_name": alert.get("name", ""),
                "status_code": msg_detail.get("status_code", ""),
                "risk": normalized_risk,
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "evidence": alert.get("evidence", ""),
                "request_header": msg_detail.get("request_header", ""),
                "response_header": msg_detail.get("response_header", ""),
                "response_body_snippet": msg_detail.get("response_body_snippet", ""),
                "response_json": msg_detail.get("response_json"),
            }
            filtered.append(entry)

        logger.info(f"[Collector] ZAP 경보 수집 완료 ─ W-1-6 관련: {len(filtered)} 건")
        return filtered

    def _fetch_message_detail(self, message_id: str) -> dict:
        """
        ZAP 메시지 ID 로 요청/응답 상세 정보를 가져옵니다.

        Args:
            message_id: ZAP 메시지 ID 문자열

        Returns:
            {status_code, request_header, response_header,
             response_body_snippet, response_json} 딕셔너리
        """
        if not message_id or self.zap is None:
            return {}

        try:
            msg = self.zap.zap.core.message(message_id)
            resp_header = msg.get("responseHeader", "")
            resp_body   = msg.get("responseBody", "")

            # 상태 코드 파싱 (예: "HTTP/1.1 200 OK" → 200)
            status_code = ""
            first_line = resp_header.split("\n")[0] if resp_header else ""
            parts = first_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])

            # 응답 본문 JSON 파싱 시도
            response_json = None
            try:
                response_json = json.loads(resp_body)
            except Exception:
                pass

            return {
                "status_code": status_code,
                "request_header": msg.get("requestHeader", ""),
                "response_header": resp_header,
                "response_body_snippet": resp_body[:500],
                "response_json": response_json,
            }
        except Exception as e:
            logger.debug(f"[Collector] 메시지 상세 조회 실패 (ID: {message_id}): {e}")
            return {}

    # -------------------------------------------------------------------------
    # CDP 로그 수집
    # -------------------------------------------------------------------------
    def collect_cdp_logs(self) -> list:
        """
        SessionManager 의 CDP 네트워크 로그에서 이상 징후를 찾습니다.

        이상 징후 판단 기준:
            - HTTP 500 이상
            - 응답 크기 1MB 이상
            - 오류 키워드 포함

        Returns:
            이상 징후 CDP 이벤트 목록
        """
        if self.session is None:
            return []

        cdp_log = self.session.get_cdp_network_log()
        anomalies = []
        error_keywords = ["error", "exception", "failed", "overflow", "memory"]

        for entry in cdp_log:
            status = entry.get("status", 0)
            size = entry.get("encoded_data_length", 0)
            body = (entry.get("response_body_snippet") or "").lower()

            is_server_error = isinstance(status, int) and status >= 500
            is_large_response = size >= 1_000_000  # 1MB 이상
            has_error_keyword = any(kw in body for kw in error_keywords)

            if not (is_server_error or is_large_response or has_error_keyword):
                continue

            risk = "HIGH" if is_server_error else "MEDIUM"
            anomaly = {
                "source": "cdp",
                "url": entry.get("url", ""),
                "status_code": status,
                "risk": risk,
                "vuln_name": "CDP 이상 징후 감지",
                "response_size_bytes": size,
                "response_body_snippet": entry.get("response_body_snippet", ""),
                "response_json": entry.get("response_json"),
            }
            anomalies.append(anomaly)

        logger.info(f"[Collector] CDP 이상 징후 수집 완료 ─ {len(anomalies)} 건")
        return anomalies

    # -------------------------------------------------------------------------
    # 결과 통합
    # -------------------------------------------------------------------------
    def merge(self, fuzzer_findings: list, target: str = "") -> list:
        """
        ZAP 경보 + 퍼저 결과 + CDP 로그를 통합합니다.
        중복 항목은 (url, vuln_name, status_code) 기준으로 제거합니다.
        결과는 위험도 내림차순으로 정렬합니다.

        Args:
            fuzzer_findings: MassiveDataFuzzer.run_all() 의 반환값
            target:          ZAP 경보 조회용 대상 URL

        Returns:
            중복 제거 + 정렬된 취약점 딕셔너리 목록
        """
        zap_findings  = self.collect_zap_alerts(target) if target else []
        cdp_findings  = self.collect_cdp_logs()

        all_findings = zap_findings + fuzzer_findings + cdp_findings

        # 중복 제거
        for f in all_findings:
            _inject_cwe_owasp(f)
            _classify_finding(f)

        unique = _dedupe_findings(all_findings)

        # 위험도 순 정렬
        triage_order = {"confirmed": 0, "suspected": 1, "noise": 2}
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        unique.sort(key=lambda x: (
            triage_order.get(x.get("triage_status", "suspected"), 1),
            RISK_ORDER.get(x.get("risk", "INFO"), 99),
            confidence_order.get(x.get("confidence", "medium"), 1),
            -int(x.get("duplicate_count", 1)),
        ))

        # CWE / OWASP 태깅 (kisa_code 또는 cwe_id/owasp_id 기반)
        logger.info(
            f"[Collector] 통합 완료 ─ ZAP:{len(zap_findings)} "
            f"퍼저:{len(fuzzer_findings)} CDP:{len(cdp_findings)} "
            f"→ 중복제거 후:{len(unique)} 건"
        )
        return unique

# =============================================================================
# CWE / OWASP 태깅 헬퍼
# =============================================================================
def _dedupe_findings(findings: list) -> list:
    grouped = {}
    for finding in findings:
        key = _dedupe_key(finding)
        if key not in grouped:
            item = dict(finding)
            item["normalized_url"] = key[2]
            item["root_cause_signature"] = key[4]
            item["duplicate_count"] = 1
            item["payload_examples"] = _compact_list([finding.get("payload_name", "")])
            item["affected_roles"] = _compact_list([finding.get("role", "")])
            item["example_urls"] = _compact_list([finding.get("url", "")])
            grouped[key] = item
            continue

        item = grouped[key]
        item["duplicate_count"] = item.get("duplicate_count", 1) + 1
        item["payload_examples"] = _compact_list(item.get("payload_examples", []) + [finding.get("payload_name", "")])
        item["affected_roles"] = _compact_list(item.get("affected_roles", []) + [finding.get("role", "")])
        item["example_urls"] = _compact_list(item.get("example_urls", []) + [finding.get("url", "")])

        if RISK_ORDER.get(finding.get("risk", "INFO"), 99) < RISK_ORDER.get(item.get("risk", "INFO"), 99):
            item["risk"] = finding.get("risk", item.get("risk"))
            item["response_text_snippet"] = finding.get("response_text_snippet", item.get("response_text_snippet", ""))
            item["response_json"] = finding.get("response_json", item.get("response_json"))

        if finding.get("elapsed_sec", 0) > item.get("elapsed_sec", 0):
            item["elapsed_sec"] = finding.get("elapsed_sec", item.get("elapsed_sec"))

    return list(grouped.values())


def _dedupe_key(finding: dict) -> tuple:
    return (
        finding.get("source", ""),
        finding.get("kisa_code", "") or finding.get("owasp", "") or finding.get("vuln_name", ""),
        _normalize_url_for_grouping(finding.get("url", "")),
        str(finding.get("status_code", "")),
        _root_cause_signature(finding),
    )


def _normalize_url_for_grouping(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlsplit(url)
        path = unquote(parsed.path)
        parts = []
        for part in path.split("/"):
            lower = part.lower()
            if not part:
                parts.append(part)
            elif part.isdigit() or len(part) > 40 or any(marker in lower for marker in INJECTION_MARKERS):
                parts.append("{input}")
            else:
                parts.append(part)
        return urlunsplit((parsed.scheme, parsed.netloc, "/".join(parts), "", ""))
    except Exception:
        return url.split("?", 1)[0]


def _root_cause_signature(finding: dict) -> str:
    snippet = (finding.get("response_text_snippet") or "").lower()
    status = str(finding.get("status_code", ""))
    patterns = [
        "httpmessagenotreadableexception",
        "json parse error",
        "cannot deserialize value",
        "methodargumenttypemismatchexception",
        "constraintviolationexception",
        "nullpointerexception",
        "sql syntax",
        "timeout",
        "root:x:",
        "index of /",
    ]
    for pattern in patterns:
        if pattern in snippet or pattern in status.lower():
            return pattern

    # 알려진 예외 패턴이 응답에 없는 5xx는 payload 이름으로 원인을 나누지 않는다.
    # 같은 endpoint에 서로 다른 payload(null/NaN/SQL 문자열/undefined 등)를 보내도
    # 전부 "그 endpoint가 잘못된 입력을 처리하지 못한다"는 동일한 코드 버그이므로,
    # endpoint(정규화된 URL) 단위로 하나의 근본원인으로 묶는다.
    if status.startswith("5"):
        endpoint = _normalize_url_for_grouping(finding.get("url", ""))
        return f"unhandled_5xx_no_input_validation::{endpoint}"

    payload = finding.get("payload_name", "")
    return re.sub(r"(_\d+k|_\d+kb|_\d+|_[a-f0-9]{8,})$", "", payload.lower())


def _classify_finding(finding: dict) -> None:
    status = finding.get("status_code")
    url = (finding.get("url") or "").lower()
    snippet = (finding.get("response_text_snippet") or "").lower()
    kisa_code = finding.get("kisa_code", "")

    confidence = "medium"
    triage = "suspected"
    reasons = []

    if status == "TIMEOUT":
        confidence = "medium"
        reasons.append("request timed out")
    elif isinstance(status, int) and status >= 500:
        confidence = "high"
        triage = "confirmed"
        reasons.append("server returned 5xx")
    elif status == 413:
        confidence = "high"
        triage = "confirmed"
        reasons.append("payload size limit exceeded")
    elif status in (200, 201):
        if kisa_code == "FU" and not any(hint in url for hint in FU_URL_HINTS):
            confidence = "low"
            triage = "noise"
            finding["risk"] = "LOW"
            reasons.append("FU payload reached non-upload endpoint")
        elif any(marker in snippet for marker in ("root:x:", "index of /", "sql syntax", "<script>alert")):
            confidence = "high"
            triage = "confirmed"
            reasons.append("response contains exploit evidence")
        else:
            confidence = "low"
            reasons.append("successful response requires manual review")

    if "jsontoken" in snippet or "json token" in snippet:
        if finding.get("risk") == "CRITICAL":
            finding["risk"] = "HIGH"
        reasons.append("JsonToken parser wording is not a secret leak")

    finding["confidence"] = confidence
    finding["triage_status"] = triage
    finding["evidence_reason"] = "; ".join(reasons) if reasons else "heuristic match"


def _compact_list(values: list, limit: int = 8) -> list:
    out = []
    for value in values:
        if value and value not in out:
            out.append(value)
        if len(out) >= limit:
            break
    return out


def _inject_cwe_owasp(finding: dict) -> None:
    """
    finding 딕셔너리에 cwe, owasp 필드를 in-place 주입.
    우선순위:
      1. finding에 이미 cwe_id/owasp_id가 있으면 그대로 사용
      2. kisa_code가 있으면 KISA_TO_CWE_OWASP 매핑 조회
      3. 매핑 없으면 빈 값
    """
    # 이미 태깅된 경우 보강만
    existing_cwe   = finding.get("cwe_id") or finding.get("cwe", [])
    existing_owasp = finding.get("owasp_id") or finding.get("owasp", "")

    if not isinstance(existing_cwe, list):
        existing_cwe = [existing_cwe] if existing_cwe else []

    kisa_code = finding.get("kisa_code", "")
    if kisa_code and kisa_code in KISA_TO_CWE_OWASP:
        cwe_list, owasp_id = KISA_TO_CWE_OWASP[kisa_code]
        if not existing_cwe:
            existing_cwe = cwe_list
        if not existing_owasp:
            existing_owasp = owasp_id

    finding["cwe"]   = existing_cwe
    finding["owasp"] = existing_owasp
    finding["owasp_name"] = OWASP_TOP10_2021.get(existing_owasp, "")