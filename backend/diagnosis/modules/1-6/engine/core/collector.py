# =============================================================================
# collector.py  ─  취약점 결과 통합 모듈
# ZAP 경보 + 퍼저 결과 + CDP 로그를 하나의 목록으로 합칩니다.
# =============================================================================

import difflib
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

from core.false_positive_rules import apply_risk_downgrade

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
INFO_LEAK_MARKERS = (
    "stack trace", "stacktrace", "traceback (most recent call last)",
    "exception in thread", "nullpointerexception", "runtimeexception",
    "methodargumenttypemismatchexception", "httpmessagenotreadableexception",
    "constraintviolationexception", "sql syntax", "sqlstate",
    "sql exception", "syntax error at or near", "select * from",
    "insert into", "delete from", "/var/", "/usr/", "/home/",
    "c:\\", "root:x:",
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
                # _classify_finding / _root_cause_signature 는 response_text_snippet 키를 읽으므로
                # 여기서 동일한 값을 별칭으로 채워 소스 간 키 불일치를 없앤다.
                "response_text_snippet": msg_detail.get("response_body_snippet", ""),
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
                # ZAP과 동일하게 response_text_snippet 별칭을 채워 분류 함수와 키를 맞춘다.
                "response_text_snippet": entry.get("response_body_snippet", ""),
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
            # response_text_snippet(퍼저) / response_body_snippet(ZAP·CDP) 둘 다 대비해 갱신
            new_snippet = _get_snippet(finding)
            if new_snippet:
                item["response_text_snippet"] = new_snippet
                item["response_body_snippet"] = new_snippet
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


def _get_snippet(finding: dict) -> str:
    """
    response_text_snippet(퍼저) 또는 response_body_snippet(ZAP/CDP) 중
    존재하는 값을 반환한다. 소스별로 키 이름이 다를 수 있으므로
    분류/시그니처 계산 지점에서 항상 이 헬퍼를 통해서만 스니펫을 읽는다.
    """
    return finding.get("response_text_snippet") or finding.get("response_body_snippet") or ""


def _root_cause_signature(finding: dict) -> str:
    snippet = _get_snippet(finding).lower()
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
    payload = finding.get("payload_name", "")
    return re.sub(r"(_\d+k|_\d+kb|_\d+|_[a-f0-9]{8,})$", "", payload.lower())


def _classify_finding(finding: dict) -> None:
    """
    finding 하나에 confidence/triage_status/evidence_reason을 in-place로 채운다.

    v6.2 업데이트: fuzzer.py가 이제 baseline 요청의 실제 응답
    (status/elapsed/body_snippet)을 finding["request_context"]에 실어 보낸다
    (request_context.baseline_verified=True인 경우에 한함 — mutating
    method이면서 ZAP 템플릿이 없는 엔드포인트는 여전히 baseline을 실측하지
    않으므로 baseline_verified=False로 남는다). 이 데이터가 있을 때는
    아래에서 실제 diff(반사 마커 / 응답 유사도 / 응답시간 배율)를 쓰고,
    없을 때는 기존 고정 문자열 매칭으로 폴백한다.

    ⚠️ 그래도 남아있는 한계 (의도적으로 미해결 — 버그 아님):

    1. 500 분기: baseline_verified=True일 때만 "baseline 정상인데 attack만
       500"을 구분해서 confirmed로 올린다. baseline_verified=False (주로
       mutating 메소드에서 ZAP 템플릿이 없는 경우)면 여전히 원래
       엔드포인트가 500이었는지 공격이 유발한 500인지 구분 못 하고,
       그 사실을 evidence_reason에 명시한 채로 confidence를 낮춘다 —
       즉 "모른다"를 정직하게 노출하는 쪽으로 바꿨을 뿐 자동으로
       완전히 닫히는 문제는 아니다.

    2. 200/201 분기: baseline diff는 이제 동작하지만 세 가지 휴리스틱
       (marker reflection, SequenceMatcher 유사도, 3배 이상 응답시간)일
       뿐 진짜 semantic diff가 아니다. 페이로드가 응답 바디에 안 나타나면서
       서버 상태만 조용히 바꾸는 business-logic 취약점(예: 과거에 잡았던
       마일리지 음수 주입처럼 응답은 200이고 바디도 baseline과 거의
       똑같은데 DB 값만 바뀌는 케이스)은 이 휴리스틱으로는 못 잡는다.
       이런 케이스는 여전히 "manual review"로 빠지도록 의도적으로 열어둠.
    """
    status = finding.get("status_code")
    url = (finding.get("url") or "").lower()
    snippet = _get_snippet(finding).lower()
    kisa_code = finding.get("kisa_code", "")
    ctx = finding.get("request_context") or {}

    confidence = "medium"
    triage = "suspected"
    reasons = []

    if status == "TIMEOUT":
        confidence = "medium"
        reasons.append("request timed out")
    elif isinstance(status, int) and status >= 500:
        if ctx.get("baseline_verified"):
            if ctx.get("baseline_valid"):
                confidence = "high"
                triage = "confirmed"
                reasons.append("verified baseline succeeded, attack payload triggered 5xx")
            else:
                confidence = "low"
                triage = "suspected"
                reasons.append("baseline itself already failed - cannot attribute 5xx to the payload")
        else:
            confidence = "medium"
            triage = "confirmed"
            reasons.append("server returned 5xx (baseline unverified for this endpoint - attribution uncertain)")
    elif status == 413:
        confidence = "low"
        triage = "noise"
        finding["risk"] = "INFO"
        reasons.append("payload size limit rejected by server")
    elif isinstance(status, int) and 400 <= status < 500:
        if any(marker in snippet for marker in INFO_LEAK_MARKERS):
            confidence = "medium"
            triage = "suspected"
            reasons.append("4xx rejection body contains internal information")
        else:
            confidence = "low"
            triage = "noise"
            finding["risk"] = "INFO"
            reasons.append("normal 4xx rejection without internal leak evidence")
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
        elif ctx.get("baseline_verified"):
            baseline_snippet = (ctx.get("baseline_body_snippet") or "").lower()
            baseline_elapsed = ctx.get("baseline_elapsed_sec")
            elapsed = finding.get("elapsed_sec")
            reflected = [m for m in INJECTION_MARKERS if m in snippet and m not in baseline_snippet]
            similarity = (difflib.SequenceMatcher(None, baseline_snippet, snippet).ratio()
                          if baseline_snippet else None)

            if reflected:
                confidence = "medium"
                triage = "suspected"
                reasons.append(f"injection marker '{reflected[0]}' present in response but absent from baseline")
            elif (isinstance(elapsed, (int, float)) and isinstance(baseline_elapsed, (int, float))
                  and baseline_elapsed > 0.05 and elapsed >= baseline_elapsed * 3 and elapsed >= 1.5):
                confidence = "medium"
                triage = "suspected"
                reasons.append(f"response time {elapsed:.2f}s is {elapsed / baseline_elapsed:.1f}x baseline "
                                f"({baseline_elapsed:.2f}s) - possible time-based blind injection")
            elif similarity is not None and similarity < 0.5:
                confidence = "medium"
                triage = "suspected"
                reasons.append(f"response body diverged from baseline (similarity {similarity:.2f})")
            elif similarity is not None and similarity >= 0.97:
                confidence = "low"
                triage = "noise"
                finding["risk"] = "INFO"
                reasons.append(f"response nearly identical to verified baseline (similarity {similarity:.2f}) "
                                "- payload had no observable effect")
            else:
                confidence = "low"
                reasons.append("successful response requires manual review (baseline diff inconclusive)")
        else:
            confidence = "low"
            reasons.append("successful response requires manual review (no verified baseline to diff against)")

    # 오탐 억제 규칙은 core/false_positive_rules.py 테이블에서 관리.
    # (fuzzer.py의 _has_real_sensitive_leak과 동일한 테이블을 공유)
    new_risk, fp_reason = apply_risk_downgrade(snippet, finding.get("risk"))
    if fp_reason:
        finding["risk"] = new_risk
        reasons.append(fp_reason)

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