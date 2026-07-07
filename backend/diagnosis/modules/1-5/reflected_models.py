"""Data models for the 1-5 Reflected redirect/forward probe (ARGUS_Backend port)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReflectedParam:
    """단일 요청 파라미터 — Phase 2(후보 선별)/Phase 3(페이로드 주입) 공통 입력 단위.

    ARGUS_Backend의 scanners.param_manipulation.CollectedParam과 동일한 필드 구성을
    그대로 유지한다 — 호출 측(기존 targets.py의 크롤링/Swagger 결과 등)에서 이 필드만
    채워주면 reflected_candidates.py/reflected_detector.py를 그대로 재사용할 수 있다.
    """

    url: str
    method: str            # GET | POST | PUT | PATCH | DELETE
    param_name: str
    param_value: str
    param_type: str = "query"   # "query" | "body" | "hidden"
    content_type: str = ""      # application/json, application/x-www-form-urlencoded 등
    raw_body: str = ""          # 이 파라미터가 속한 요청의 전체 baseline body (JSON/form)


@dataclass
class RedirectCandidate:
    """이름 기반 규칙으로 리다이렉트/포워드 후보로 태깅된 파라미터 — Phase 2 산출물."""

    collected: ReflectedParam
    reason: str  # 후보로 선정된 근거 (매칭된 규칙 설명)


@dataclass
class RedirectFinding:
    """
    Reflected 리다이렉트/포워드 판별 결과 — Phase 3 산출물.

    detection_type:
        LOCATION_HEADER  3xx 응답의 Location 헤더에 주입한 외부 목적지가 그대로 노출
                         (서버 사이드 리다이렉트 — 가장 확실한 증거)
        META_REFRESH     200 응답 본문의 <meta http-equiv="refresh" ... url=...>에
                         주입한 외부 목적지가 그대로 노출 (클라이언트 사이드)
        JS_REDIRECT      200 응답 본문의 location.href / location.replace(/.assign() 등
                         JS 대입문에 주입한 외부 목적지가 그대로 노출 (클라이언트 사이드)
        REFLECTED_VALUE  위 세 리다이렉트 문맥에 해당하지 않지만, 성공 응답(2xx)의 본문에
                         주입한 외부 목적지 문자열이 그대로 반사(echo)됨 (실제 리다이렉트
                         실행 증거는 없음 — 반사만 확인된 상태). 4xx/5xx 실패 응답에서의
                         반사는 값이 어떤 로직에도 도달하지 못했다는 뜻이라 대상에서 제외한다.

    severity: HIGH(서버 사이드 확정) | MEDIUM(클라이언트 사이드 — 실제 렌더링/실행 여부는
              브라우저 재현으로 추가 확인 권장) | LOW(단순 반사 — 리다이렉트 실행 증거 없음)

    confirmed_redirect: 실제 리다이렉트 실행 증거(Location/meta refresh/JS 대입)가 있으면
              True (LOCATION_HEADER/META_REFRESH/JS_REDIRECT). REFLECTED_VALUE처럼 값이
              반사된 것만 확인되고 리다이렉트 실행 증거가 없으면 False — 1-5 확정
              취약점이 아니라 참고용 정보 노출 신호로 별도 취급해야 한다.
    """

    url: str
    method: str
    param_name: str
    payload_used: str
    payload_description: str
    detection_type: str
    evidence: str          # Location 헤더 값 또는 매칭된 본문 스니펫
    baseline_status: int
    test_status: int
    severity: str
    description: str
    recommendation: str
    confirmed_redirect: bool = True  # False면 "반사만 확인됨" — 리다이렉트 실행 증거 없음
    request_body: str = ""  # 실제 전송한 테스트 요청 바디/쿼리 (증적)
