"""
ARGUS - SSRF / File Inclusion 진단 모듈

세 가지 입력 소스(URL List / API List / Swagger)를 단일 ScanTarget 객체로
정규화하기 위한 공통 데이터 모델을 정의합니다.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, parse_qs


class DetectionSource(str, Enum):
    """탐지 출처 - ZAP Active Scan vs 자체 페이로드 인젝터"""
    ZAP_ACTIVE_SCAN = "ZAP_ACTIVE_SCAN"
    CUSTOM_INJECTOR = "CUSTOM_INJECTOR"


class InputSource(str, Enum):
    """입력 소스 종류"""
    URL_LIST = "URL_LIST"
    API_LIST = "API_LIST"
    SWAGGER = "SWAGGER"


class ParamLocation(str, Enum):
    """파라미터 위치"""
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"


class VulnType(str, Enum):
    """가이드라인 1-4 기준 취약점 분류"""
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    SSRF = "Server-Side Request Forgery"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanParam:
    """스캔 대상이 되는 개별 파라미터"""
    name: str                              # 파라미터명 (예: url, file, redirect)
    location: ParamLocation                # query / path / body / header
    required: bool = False
    schema: Optional[dict] = None
    sample_value: Optional[str] = None      # 원본 예시 값 (있는 경우)


@dataclass
class ScanTarget:
    """
    URL List / API List / Swagger 입력을 정규화한 단일 스캔 대상 모델.
    검색 엔진과 페이로드 인젝터는 오직 이 객체만 바라봅니다.
    """
    method: str                            # GET, POST, PUT, DELETE ...
    base_url: str                          # 스킴+호스트 (예: https://target.com)
    path: str                              # 경로 (예: /api/v1/profile/image)
    params: list = field(default_factory=list)   # list[ScanParam]
    tags: list = field(default_factory=list)     # OpenAPI operation tags
    # OpenAPI x-roles/x-allowed-roles declaration. Role names are intentionally dynamic.
    allowed_roles: list = field(default_factory=list)
    source: InputSource = InputSource.URL_LIST
    raw: Optional[str] = None              # 원본 입력 (디버깅/로그용)
    content_type: str = ""                 # OpenAPI requestBody media type

    @property
    def full_url(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.path}"

    @staticmethod
    def from_raw_url(raw_url: str) -> "ScanTarget":
        """
        URL List 입력 한 줄을 ScanTarget으로 변환합니다.
        예: https://target.com/view?file=report.pdf&redirect=https://a.com
        """
        parsed = urlparse(raw_url.strip())
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        query_params = parse_qs(parsed.query)

        params = [
            ScanParam(
                name=key,
                location=ParamLocation.QUERY,
                sample_value=values[0] if values else None,
            )
            for key, values in query_params.items()
        ]

        return ScanTarget(
            method="GET",
            base_url=base_url,
            path=path,
            params=params,
            source=InputSource.URL_LIST,
            raw=raw_url,
        )
