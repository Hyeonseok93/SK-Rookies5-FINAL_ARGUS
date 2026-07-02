"""
ARGUS - SSRF / File Inclusion 진단 모듈

"Web/API 개발보안 Guideline (2022년) v3.0.0" - 1-4. SSRF / File Inclusion 공격 가능성
항목을 기준으로, ScanTarget 목록에서 SSRF/File Inclusion 가능성이 있는
파라미터를 1차로 선별하는 "검색 엔진"입니다.

이 단계는 실제 공격을 수행하지 않고, 의심 파라미터를 빠르게 좁히는
정적 분석(Static Triage) 역할을 합니다. 실제 취약점 존재 여부 검증은
payload_injector.py가 담당합니다.

판단 기준 (가이드라인 본문 발췌 요약):
  - File Inclusion: 파라미터로 "파일 경로"를 받아 include/open에 사용
      예) errorPath=../../../../etc/passwd (LFI)
          errorPath=http://vulnerability.com/exploit (RFI)
  - SSRF: 파라미터로 "URL/IP"를 받아 서버가 대신 요청
      예) url=http://192.168.x.x/security (내부망 접근)
          url=http://localhost/admin (외부 차단된 관리자 페이지 접근)
          url=http://skshieldus.com@http://192.168.x.x (도메인 검증 우회)
          url=file:///etc/passwd (서버 내 파일 열람)
"""

import re
from dataclasses import dataclass, field
from typing import List

from models import ScanTarget, ScanParam, VulnType, RiskLevel


# --------------------------------------------------------------------------
# 1. 파라미터명 키워드 사전
#    가이드라인 본문의 "파라미터(경로) 값" 표현 + 실무에서 흔히 쓰이는 변형명을 포함
# --------------------------------------------------------------------------
SSRF_PARAM_KEYWORDS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "origin",
    "redirect", "redirect_uri", "return", "returnurl", "next",
    "target", "callback", "callback_url", "webhook", "endpoint",
    "host", "domain", "site", "proxy", "fetch", "download_url",
    "image_url", "imageurl", "avatar_url", "feed", "feed_url", 
    "target", "redirect", "logo", "logo_url", "logourl", "image",
    "thumbnail", "thumbnail_url", "thumbnailurl",
]

FILE_INCLUSION_PARAM_KEYWORDS = [
    "file", "filename", "filepath", "path", "page", "doc", "document",
    "template", "tpl", "view", "include", "load", "read", "report",
    "errorpath", "error_path", "dir", "folder", "attachment", "resource",
]

# --------------------------------------------------------------------------
# 2. 값(value) 패턴 - 샘플 값이 존재하는 경우 (Swagger example, API List 등) 검사
# --------------------------------------------------------------------------
VALUE_PATTERNS = {
    "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.%2[fF]|%2e%2e[/\\])"),
    "ABSOLUTE_UNIX_PATH": re.compile(r"^/etc/|^/proc/|^/var/"),
    "FILE_SCHEME": re.compile(r"^file://", re.IGNORECASE),
    "DANGEROUS_SCHEME": re.compile(r"^(dict|gopher|ftp|jar|expect)://", re.IGNORECASE),
    "EXTERNAL_URL": re.compile(r"^https?://", re.IGNORECASE),
    "INTERNAL_IP_HINT": re.compile(
        r"(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})"
    ),
    "AT_SIGN_BYPASS": re.compile(r"@https?://"),  # 도메인 검증 우회 (가이드라인 예시 패턴)
}

STRUCTURED_STRING_FORMATS = {
    "date", "date-time", "time", "email", "uuid", "duration",
    "hostname", "ipv4", "ipv6", "binary", "byte",
}

PLACE_PARAM_NAMES = {
    "origin", "destination", "departure", "arrival",
    "fromplace", "toplace", "fromlocation", "tolocation",
}
DATE_FORMATS = {"date", "date-time"}


def _is_constrained_param(param: ScanParam) -> bool:
    """OpenAPI상 자유 문자열 페이로드를 받을 수 없는 파라미터인지 확인합니다."""
    schema = param.schema or {}
    schema_type = schema.get("type", "").lower()
    if schema.get("enum") or schema.get("format", "").lower() in STRUCTURED_STRING_FORMATS:
        return True
    normalized_name = re.sub(r"[^a-z0-9]", "", param.name.lower())
    sibling_formats = {
        str(value).lower() for value in schema.get("x-argus-sibling-formats", [])
    }
    if normalized_name in PLACE_PARAM_NAMES and sibling_formats.intersection(DATE_FORMATS):
        return True
    if schema_type == "object":
        return True
    if schema_type == "array":
        item_schema = schema.get("items", {})
        item_param = ScanParam(param.name, param.location, schema=item_schema)
        return _is_constrained_param(item_param)
    return False


@dataclass
class SearchHit:
    """검색 엔진이 식별한 의심 파라미터 1건"""
    target: ScanTarget
    param: ScanParam
    vuln_type: VulnType
    risk_level: RiskLevel
    matched_reasons: list = field(default_factory=list)  # 어떤 규칙에 걸렸는지 기록

    def to_dict(self) -> dict:
        return {
            "method": self.target.method,
            "url": self.target.full_url,
            "param": self.param.name,
            "location": self.param.location.value,
            "vuln_type": self.vuln_type.value,
            "risk_level": self.risk_level.value,
            "matched_reasons": self.matched_reasons,
            "source": self.target.source.value,
        }


def _classify_param_name(param_name: str) -> VulnType:
    """파라미터명만으로 1차 분류 (SSRF vs File Inclusion vs Unknown)"""
    normalized_name = re.sub(r"[^a-z0-9]", "", param_name.lower())

    ssrf_keywords = {
        re.sub(r"[^a-z0-9]", "", keyword.lower()) for keyword in SSRF_PARAM_KEYWORDS
    }
    file_keywords = {
        re.sub(r"[^a-z0-9]", "", keyword.lower())
        for keyword in FILE_INCLUSION_PARAM_KEYWORDS
    }

    if normalized_name in ssrf_keywords:
        return VulnType.SSRF
    if normalized_name in file_keywords:
        return VulnType.LFI  # RFI 여부는 값 패턴 검사에서 추가 판단

    # Exact matching remains the strongest signal, but plural/suffixed API field
    # names (imageUrls, callbackEndpointValue, templateName) must not disappear.
    # Require a meaningful keyword length to avoid tiny fragments such as "url"
    # matching unrelated words.
    if any(len(keyword) >= 5 and keyword in normalized_name for keyword in ssrf_keywords):
        return VulnType.SSRF
    if any(len(keyword) >= 5 and keyword in normalized_name for keyword in file_keywords):
        return VulnType.LFI

    return VulnType.UNKNOWN


def _inspect_value(value: str) -> List[str]:
    """샘플 값에서 위험 패턴을 검사하고, 매칭된 규칙명 리스트를 반환"""
    if not value:
        return []

    reasons = []
    for rule_name, pattern in VALUE_PATTERNS.items():
        if pattern.search(value):
            reasons.append(rule_name)
    return reasons


def _calculate_risk(vuln_type: VulnType, name_matched: bool, value_reasons: List[str]) -> RiskLevel:
    """
    위험도 스코어링.
    - 파라미터명 매칭 + 값 패턴 매칭이 동시에 있으면 HIGH
    - 위험 스킴(file://, dict:// 등) 또는 내부 IP 힌트가 보이면 즉시 HIGH (가이드라인 대응방안의 역기준)
    - 파라미터명만 매칭되면 MEDIUM (실제 검증 필요)
    - 값 패턴만 매칭되면 MEDIUM
    """
    critical_rules = {"FILE_SCHEME", "DANGEROUS_SCHEME", "INTERNAL_IP_HINT",
                       "AT_SIGN_BYPASS", "PATH_TRAVERSAL", "ABSOLUTE_UNIX_PATH"}

    if any(r in critical_rules for r in value_reasons):
        return RiskLevel.HIGH

    if name_matched and value_reasons:
        return RiskLevel.HIGH

    if name_matched or value_reasons:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def search_targets(targets: List[ScanTarget]) -> List[SearchHit]:
    """
    ScanTarget 리스트 전체를 검색하여 SSRF/File Inclusion 의심 파라미터를 식별합니다.
    이것이 "Build Attack Tree"에서 말하는 검색 엔진의 핵심 로직입니다.
    """
    hits: List[SearchHit] = []

    for target in targets:
        for param in target.params:
            schema_type = (param.schema or {}).get("type", "").lower()
            if schema_type in {"integer", "number", "boolean"}:
                continue
            if _is_constrained_param(param):
                continue

            vuln_type = _classify_param_name(param.name)
            sibling_names = {
                re.sub(r"[^a-z0-9]", "", str(name).lower())
                for name in (param.schema or {}).get("x-argus-sibling-names", [])
            }
            if (
                re.sub(r"[^a-z0-9]", "", param.name.lower()) == "template"
                and "report" in target.path.lower()
                and "logourl" in sibling_names
            ):
                vuln_type = VulnType.SSRF
            name_matched = vuln_type != VulnType.UNKNOWN

            value_reasons = _inspect_value(param.sample_value or "")

            # 값 패턴으로 RFI 재분류 (파라미터명은 file류인데 값이 외부 URL인 경우)
            if vuln_type == VulnType.LFI and "EXTERNAL_URL" in value_reasons:
                vuln_type = VulnType.RFI

            # 파라미터명 매칭이 없어도 값 패턴이 치명적이면 보고 대상에 포함
            if not name_matched and not value_reasons:
                continue

            risk = _calculate_risk(vuln_type, name_matched, value_reasons)

            hits.append(
                SearchHit(
                    target=target,
                    param=param,
                    vuln_type=vuln_type if vuln_type != VulnType.UNKNOWN else VulnType.SSRF,
                    risk_level=risk,
                    matched_reasons=(
                        (["PARAM_NAME_KEYWORD"] if name_matched else []) + value_reasons
                    ),
                )
            )

    # 위험도 높은 순으로 정렬
    risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}
    hits.sort(key=lambda h: risk_order[h.risk_level])

    return hits
