"""Deterministic 7-4 test descriptions and remediation guidance."""

from __future__ import annotations

from dataclasses import dataclass


GUIDELINE_REFERENCE = "ARGUS 웹/API 개발보안 권고 · 7-4 취약한 보안설정 기준"
DEPENDENCY_FILE_REQUIRED = (
    "오픈소스 의존성 취약점(SCA) 점검에는 deps 파일을 반드시 첨부해야 합니다. "
    "API List, URL List, Swagger 및 Base URL만으로는 서버에 실제 설치된 라이브러리와 정확한 버전을 "
    "확인할 수 없기 때문입니다. deps 파일의 실제 의존성 트리를 기준으로 구성요소와 버전을 식별해야 "
    "취약 버전 범위를 정확히 대조하고 오탐을 방지할 수 있습니다."
)


@dataclass(frozen=True, slots=True)
class WebGuidance:
    label: str
    impact: str
    remediation: tuple[str, ...]


_WEB: dict[str, WebGuidance] = {
    "no_transport_encryption": WebGuidance(
        "전송구간 암호화 미적용",
        "네트워크 구간에서 인증정보 및 중요정보가 노출되거나 요청·응답이 변조될 가능성",
        (
            "모든 웹/API 통신에는 신뢰할 수 있는 인증서를 적용한 HTTPS/TLS를 사용해야 합니다.",
            "HTTP 요청은 HTTPS로 강제 전환하고, HTTPS 응답에는 Strict-Transport-Security를 설정해야 합니다.",
        ),
    ),
    "missing_hsts": WebGuidance(
        "HSTS 미설정",
        "SSL Stripping을 통한 평문 통신 유도와 중간자 공격이 발생할 가능성",
        (
            "HTTPS 응답에 Strict-Transport-Security: max-age=31536000; includeSubDomains를 설정해야 합니다.",
            "충분한 사전 검증 후 필요하면 preload 정책을 적용하고 모든 하위 도메인의 HTTPS 지원 여부를 확인해야 합니다.",
        ),
    ),
    "missing_csp": WebGuidance(
        "Content-Security-Policy 미설정",
        "악성 스크립트와 비인가 외부 리소스가 브라우저에서 실행될 가능성",
        (
            "서비스에서 필요한 출처만 허용하도록 Content-Security-Policy를 서버 응답 헤더에 설정해야 합니다.",
            "unsafe-inline 및 unsafe-eval 사용을 최소화하고 nonce 또는 hash 기반 정책을 적용해야 합니다.",
        ),
    ),
    "missing_x_frame_options": WebGuidance(
        "클릭재킹 방어 헤더 미설정",
        "외부 사이트의 프레임에 서비스 화면이 삽입되어 사용자의 의도하지 않은 행위가 실행될 가능성",
        (
            "X-Frame-Options를 DENY 또는 SAMEORIGIN으로 설정해야 합니다.",
            "CSP를 사용하는 경우 frame-ancestors 지시어로 허용 가능한 프레임 출처를 제한해야 합니다.",
        ),
    ),
    "weak_x_frame_options": WebGuidance(
        "클릭재킹 방어 헤더 설정 미흡",
        "외부 프레임 삽입을 차단하지 못해 클릭재킹 공격이 발생할 가능성",
        (
            "효력이 없는 ALLOWALL 설정을 제거하고 X-Frame-Options를 DENY 또는 SAMEORIGIN으로 설정해야 합니다.",
            "CSP frame-ancestors 정책도 함께 적용해 허용 출처를 명시적으로 제한해야 합니다.",
        ),
    ),
    "missing_nosniff": WebGuidance(
        "MIME 스니핑 방지 설정 미흡",
        "브라우저가 응답 형식을 잘못 해석하여 업로드 파일 등의 비실행 콘텐츠가 실행될 가능성",
        ("모든 응답에 X-Content-Type-Options: nosniff를 설정하고 정확한 Content-Type을 반환해야 합니다.",),
    ),
    "missing_referrer_policy": WebGuidance(
        "Referrer-Policy 미설정",
        "외부 사이트로 이동할 때 URL에 포함된 경로와 질의정보가 Referer 헤더로 노출될 가능성",
        ("Referrer-Policy를 strict-origin-when-cross-origin 이상으로 설정하고 민감정보를 URL에 포함하지 않아야 합니다.",),
    ),
    "missing_permissions_policy": WebGuidance(
        "Permissions-Policy 미설정",
        "카메라·마이크·위치정보 등 불필요한 브라우저 기능이 사용될 가능성",
        ("Permissions-Policy 헤더를 설정해 서비스에서 사용하지 않는 브라우저 기능을 명시적으로 차단해야 합니다.",),
    ),
    "cookie_missing_secure": WebGuidance(
        "쿠키 Secure 속성 미설정",
        "세션 쿠키가 암호화되지 않은 통신으로 전송되어 탈취될 가능성",
        ("인증 및 세션 쿠키에 Secure 속성을 설정하고 HTTPS에서만 전송되도록 해야 합니다.",),
    ),
    "cookie_missing_httponly": WebGuidance(
        "쿠키 HttpOnly 속성 미설정",
        "스크립트를 통해 세션 쿠키가 탈취될 가능성",
        ("인증 및 세션 쿠키에 HttpOnly 속성을 설정해 클라이언트 스크립트의 접근을 차단해야 합니다.",),
    ),
    "cookie_missing_samesite": WebGuidance(
        "쿠키 SameSite 속성 미설정",
        "외부 사이트에서 인증 쿠키가 함께 전송되어 CSRF 공격이 발생할 가능성",
        ("업무 흐름을 검토해 인증 및 세션 쿠키에 SameSite=Lax 또는 Strict를 설정해야 합니다.",),
    ),
}

_DEFAULT = WebGuidance(
    "취약한 보안설정",
    "보안 통제가 우회되어 중요정보 노출, 세션 탈취 또는 사용자 행위 위조가 발생할 가능성",
    (
        "보안 설정은 애플리케이션 코드와 배포 환경에서 일관되게 적용하고 서버 응답으로 검증해야 합니다.",
        "개발·검수·운영 환경에 동일한 보안 기준을 적용하고 배포 전 자동 점검을 수행해야 합니다.",
    ),
)


def web_guidance(check_type: str) -> WebGuidance:
    return _WEB.get(check_type, _DEFAULT)


def web_test_method(check_type: str, header: str) -> str:
    target = header or check_type
    return (
        f"대상 URL에 직접 HTTP 요청을 전송하고 실제 응답 헤더와 통신 방식을 수집한 후, `{target}` 설정의 "
        "존재 여부와 값이 보안 기준을 충족하는지 확인했습니다. 동일 항목이 여러 URL에서 발견된 경우 "
        "대표 증거와 전체 영향 URL을 함께 비교했습니다."
    )


def sca_test_method() -> str:
    return (
        "deps 파일에서 실제 설치된 직접·간접 의존성의 구성요소명과 버전을 추출하고, 해당 버전을 "
        "OSV 및 공개 보안 권고의 취약 버전 범위와 대조했습니다. " + DEPENDENCY_FILE_REQUIRED
    )
