"""Data models for the 1-5 Reflected XSS probe (reflected_models.py의 XSS 변형)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class XssFinding:
    """
    반사형 XSS 판별 결과.

    severity/confirmed:
        HIGH / confirmed=True   응답 Content-Type이 text/html — 브라우저가 그대로 파싱해
                                 스크립트가 실행될 수 있는 확정 반사형 XSS.
        LOW  / confirmed=False  응답이 HTML이 아님(JSON 등) — 페이로드가 이스케이프 없이
                                 반사되는 것은 확인됐지만, 실제 실행 여부는 프런트엔드가
                                 이 값을 안전하지 않게 렌더링하는지에 달려 있어 후보로만
                                 표시한다.
    """

    url: str
    method: str
    param_name: str
    payload_used: str
    payload_description: str
    evidence: str
    baseline_status: int
    test_status: int
    content_type: str
    severity: str
    confirmed: bool
    description: str
    recommendation: str
    request_body: str = ""
    # True면 evidence 스니펫이 method(PATCH/POST 등) 요청 자체의 응답이 아니라, 그 직후
    # 별도로 보낸 GET 재조회 응답이다 — PATCH 자체는 상태 메시지만 돌려주고 저장된 값을
    # 보여주지 않는 API(예: 프로필 수정)에서 값이 실제로 저장됐는지 확인하려고 덧붙인
    # 요청이라, 화면에 "재조회(GET) 응답"이라고 명확히 구분해 표시해야 한다.
    stored: bool = False
