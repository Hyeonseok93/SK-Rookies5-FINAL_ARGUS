import time
import os
import json
import html
import re
import base64
import hashlib
import urllib.parse
import requests
from datetime import date, datetime, timedelta, timezone
from zapv2 import ZAPv2

# 전역 스캔 상태 관리
scan_status = {
    "is_running": False,
    "progress": 0,
    "message": "Ready",
    "result_file": None,
    "log_file": None,
    "total_alerts": 0
}

result_dir_override = None

def update_status(is_running=None, progress=None, message=None, result_file=None, log_file=None, total_alerts=None):
    if is_running is not None: scan_status["is_running"] = is_running
    if progress is not None: scan_status["progress"] = progress
    if message is not None: scan_status["message"] = message
    if result_file is not None: scan_status["result_file"] = result_file
    if log_file is not None: scan_status["log_file"] = log_file
    if total_alerts is not None: scan_status["total_alerts"] = total_alerts
    try:
        from app.services import diagnosis_progress as dp

        if is_running is False:
            if progress == 100:
                dp.finish(message or "1-1 scan completed")
            elif message:
                dp.fail(message)
        else:
            dp.update(
                phase="running",
                message=message,
                percent=progress,
            )
    except Exception:
        pass

def get_payload_reflection(payload, response_body):
    if not payload or not response_body:
        return None

import difflib
import copy

def normalize_reflection_text(value: str = "") -> str:
    if not value:
        return ""
    text = str(value)
    for _ in range(2):
        text = html.unescape(urllib.parse.unquote_plus(text))
        text = (
            text.replace("\\/", "/")
                .replace("\\u003c", "<")
                .replace("\\u003C", "<")
                .replace("\\u003e", ">")
                .replace("\\u003E", ">")
                .replace("\\u002f", "/")
                .replace("\\u002F", "/")
        )
    return text

def get_payload_reflection(payload, response_body, baseline_body=None):
    if not payload or not response_body:
        return None

    # Baseline이 지정된 경우 diff 분석을 수행해 새로 추가된 영역만 분리
    active_text = response_body
    if baseline_body:
        try:
            # difflib.ndiff를 활용해 추가(+)된 라인 및 문자들을 결합하여 새로 유입된 문자열 추출
            diff = difflib.ndiff(baseline_body.splitlines(keepends=True), response_body.splitlines(keepends=True))
            added_lines = [line[2:] for line in diff if line.startswith('+ ')]
            active_text = "".join(added_lines)
            if not active_text.strip():
                # 추가된 신규 텍스트가 없는 경우 반사되지 않은 것으로 확정
                return None
        except Exception:
            active_text = response_body

    payload_variants = {
        payload,
        normalize_reflection_text(payload),
        html.escape(payload),
        html.escape(payload, quote=False),
        urllib.parse.quote(payload),
        urllib.parse.quote_plus(payload),
        payload.replace("/", "\\/"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E"),
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("/", "\\/"),
        payload.replace("<", "\\u003C").replace(">", "\\u003E").replace("/", "\\/"),
    }
    body_variants = {
        active_text,
        normalize_reflection_text(active_text),
    }

    for body in body_variants:
        for variant in payload_variants:
            normalized_variant = normalize_reflection_text(variant)
            if normalized_variant and normalized_variant.lower() in body.lower():
                return variant
    return None

def is_payload_reflected(payload, response_body, baseline_body=None):
    return get_payload_reflection(payload, response_body, baseline_body) is not None

def find_json_keypaths_containing(value, payload, prefix=""):
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            matches.extend(find_json_keypaths_containing(child, payload, path))
    elif isinstance(value, str) and payload in value:
        matches.append(prefix)
    return matches

def normalize_response_param_path(path):
    parts = [part for part in str(path).split(".") if part and not part.isdigit()]
    if parts and parts[0] in {"data", "items", "result", "results"}:
        parts = parts[1:]
    if parts and parts[0].endswith("s") and len(parts) > 1:
        parts = parts[1:]
    return ".".join(parts) if parts else path

def infer_reflected_response_params(response, payload):
    try:
        body = response.json()
    except Exception:
        return []
    params = []
    for path in find_json_keypaths_containing(body, payload):
        normalized = normalize_response_param_path(path)
        if normalized and normalized not in params:
            params.append(normalized)
    return params

def detect_xss_reflection_context(payload, response_body):
    if not payload or not response_body:
        return "unknown"

    bodies = [
        response_body,
        html.unescape(response_body),
        urllib.parse.unquote_plus(response_body),
    ]
    payload_re = re.escape(payload)
    for body in bodies:
        if re.search(r"<[^>]+\s[\w:-]+\s*=\s*(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "HTML attribute"
        if re.search(r">\s*" + payload_re + r"\s*<", body, re.IGNORECASE):
            return "HTML body"
        if re.search(r"(['\"])" + payload_re + r"\1", body, re.IGNORECASE):
            return "JSON/String value"
    return "encoded/reflected"

def classify_xss_response(payload, response_body, content_type, method="GET", is_mutation=False, response_headers=None, baseline_body=None):
    if not payload or not response_body:
        return None

    response_lower = response_body.lower()
    decoded_response_body = normalize_reflection_text(response_body)
    decoded_response_lower = decoded_response_body.lower()
    content_type_lower = (content_type or "").lower()
    headers = response_headers or {}
    x_content_type = (headers.get("X-Content-Type-Options", "") or "").lower()

    source_indicators = ["location", "search", "document.cookie", "document.location", "url", "query", "param", "input"]
    dom_sink_patterns = [
        "document.write",
        "document.writeln",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "eval(",
        "settimeout(",
        "setinterval(",
        "window.location",
        "document.location",
        "location.href",
        "appendchild",
        "insertbefore",
    ]
    # 응답 본문에 페이로드가 실행 가능한 형태로 반사되었는지 판별하는 마커
    executable_markers = ["<script", "</script>", "onerror=", "onload=", "onclick=", "javascript:", "<svg", "<img", "<iframe"]

    reflected_variant = get_payload_reflection(payload, response_body, baseline_body)
    has_payload_in_body = reflected_variant is not None
    has_dom_sink = any(pattern in decoded_response_lower for pattern in dom_sink_patterns)
    has_source_indicator = any(indicator in decoded_response_lower for indicator in source_indicators)
    has_user_input_reference = "userinput" in response_lower or "input" in response_lower
    has_executable_marker = any(marker in decoded_response_lower for marker in executable_markers)

    # ── DOM XSS 의심 패턴 (정적 분석으로는 확정 불가 → Informational 강등) ──────────────
    # DOM XSS 실제 탐지는 Playwright 헤드리스 브라우저를 통한 동적 실행 검증만 가능.
    # 여기서는 "의심 패턴이 발견됨"을 리포팅하고 Playwright 위임 힌트를 남긴다.
    if has_dom_sink and (has_source_indicator or has_user_input_reference) and (has_payload_in_body or has_executable_marker):
        detected_sinks = ", ".join([p for p in dom_sink_patterns if p in response_lower])
        return {
            "kind": "dom_suspect",
            "custom_type": "DOM_XSS_SUSPECT",
            "risk": "Informational",
            "confidence": "Low",
            "alert": "[정적 분석] DOM XSS 의심 패턴 감지 — Playwright 동적 검증 필요",
            "description": (
                "응답 본문에서 DOM 삽입 지점과 사용자 입력 경로 신호가 동시에 발견되었습니다. "
                "단, 정적 텍스트 분석으로는 실제 취약 여부를 확정할 수 없습니다. "
                "Playwright 헤드리스 브라우저에서 페이지를 직접 로드하고 alert() 발화 여부를 모니터링하는 동적 검증이 필요합니다."
            ),
            "evidence": f"응답 본문에 DOM 삽입 지점({detected_sinks})이 감지되었습니다.",
            "playwright_action": "url_param_injection",
        }

    if not has_payload_in_body:
        return None

    is_html_context = "html" in content_type_lower
    is_json_context = "json" in content_type_lower
    has_nosniff = "nosniff" in x_content_type
    reflection_context = detect_xss_reflection_context(payload, response_body)

    # ── Reflected XSS ──────────────────────────────────────────────────────────────────
    # POST/PUT 등 쓰기 메서드라도 응답에 페이로드가 에코백 되면 Reflected XSS.
    # 진짜 Stored XSS는 POST 저장 후 GET 재조회 응답에서만 판정 가능하며,
    # 해당 로직은 run_zap_scan() 내부의 2단계 저장-재조회 루프에서 별도 처리한다.
    # ── Reflected XSS ──────────────────────────────────────────────────────────────────
    # POST/PUT 등 쓰기 메서드라도 응답에 페이로드가 에코백 되면 Reflected XSS.
    # 진짜 Stored XSS는 POST 저장 후 GET 재조회 응답에서만 판정 가능하며,
    # 해당 로직은 run_zap_scan() 내부의 2단계 저장-재조회 루프에서 별도 처리한다.
    if (is_html_context or is_json_context) and has_executable_marker:
        if is_html_context:
            risk = "Medium"
            confidence = "High"
            desc = (
                "응답 본문에 XSS 공격 페이로드가 HTML 인코딩 없이 그대로 반사되었습니다. "
                "프론트엔드에서 직접 화면에 출력하거나 innerHTML 등으로 이 값을 렌더링할 경우 브라우저 런타임에서 즉시 악성 스크립트가 실행됩니다. "
                f"(Content-Type: {content_type}, Context: {reflection_context})"
            )
            sol = "특수 문자(<, >, &, \", ')가 입력되거나 출력되는 시점에 HTML Entity Escape 처리를 적용하여 브라우저가 스크립트로 오인하지 않도록 차단하십시오."
        else:
            # JSON context 내 반사 케이스 (프론트엔드 바인딩 위협)
            risk = "Low"
            confidence = "Medium"
            desc = (
                "요청으로 전송된 XSS 페이로드가 API 응답 JSON 데이터 내에 필터링 없이 그대로 출력되었습니다. "
                "모던 프론트엔드 프레임워크(React, Vue 등)의 기본 이스케이프 정책 덕분에 브라우저에서의 실제 실행은 제한될 수 있습니다. "
                "다만, dangerouslySetInnerHTML, v-html과 같은 안전하지 않은 속성 바인딩을 사용하거나, WebView/이메일 템플릿 등으로 활용 영역이 확장될 경우 즉시 XSS 공격 경로로 이어질 위험이 존재합니다. (서버 측의 2차 방어선 누락)"
            )
            sol = "프론트엔드 수준의 방어에만 의존하지 말고, 서버 측 인풋 유효성 검증 단(XssEscapeServletFilter 등) 또는 JSON Response 직렬화 단계에서 특수 문자 필터링을 적용하여 일관적인 데이터 보안 상태를 유지하십시오."

        return {
            "kind": "reflected",
            "custom_type": "40012",
            "risk": risk,
            "confidence": confidence,
            "alert": "Reflected Cross-Site Scripting (Reflected XSS) Vulnerability",
            "description": desc,
            "solution": sol,
            "evidence": f"Response body reflected payload variant '{reflected_variant}' from original payload '{payload}'.",
            "reflection_context": reflection_context,
            "reflected_variant": reflected_variant,
        }

    return None


def classify_alert(alert_name, param_name, attack_val, description, custom_type=None):
    an = alert_name.lower()
    desc = description.lower()
    pn = param_name.lower()

    # ── custom_type 완전 일치 우선 분기 (문자열 패턴 매칭보다 먼저 처리) ──────────────────
    if custom_type == "40012":
        return "1-1", "Reflected XSS", "중요", "입력값이 응답 본문에 그대로 반사되어 브라우저에서 실행될 수 있습니다."
    if custom_type == "40014":
        return "1-1", "Stored XSS", "중요", "저장된 입력값이 이후 응답 렌더링 단계에서 다시 실행 가능한 형태로 노출됩니다."
    if custom_type == "DOM_XSS_CUSTOM":
        return "1-1", "DOM XSS", "중요", "클라이언트 측 DOM 삽입 경로를 통해 사용자 입력이 실행 가능한 코드로 처리될 수 있습니다."
    if custom_type == "DOM_XSS_SUSPECT":
        return "1-1", "DOM XSS", "참고", "[정적 분석] DOM 삽입 지점 의심 패턴이 감지되었습니다. Playwright 동적 검증을 통한 실제 실행 여부 확인이 필요합니다."
    if custom_type == "CSRF_CUSTOM":
        return "1-1", "CSRF", "중요", "쿠키 기반 인증만으로 상태 변경 요청이 통과되어 외부 사이트에서의 위조 요청 공격이 가능합니다."
    if custom_type == "CORS_ORIGIN_REFLECTION":
        return "1-1", "CORS Origin Reflection", "중요", "서버가 임의 Origin을 ACAO 헤더에 그대로 반사하고 Credentials를 허용하여 공격 도메인에서 인증된 API 요청이 가능합니다."
    if custom_type == "MIME_SNIFF_CUSTOM":
        return "7-4", "취약한 보안설정", "일반", "X-Content-Type-Options: nosniff 헤더가 누락되어 브라우저가 응답을 HTML로 오인 파싱할 수 있습니다."
    if custom_type == "REFERRER_POLICY_CUSTOM":
        return "7-4", "취약한 보안설정", "일반", "Referrer-Policy 헤더가 누락되어 내부 API URL 및 토큰 정보가 외부 도메인으로 유출될 수 있습니다."
    if custom_type == "PERMISSIONS_POLICY_CUSTOM":
        return "7-4", "취약한 보안설정", "일반", "Permissions-Policy 헤더가 누락되어 브라우저 하드웨어 API(카메라, 마이크 등) 접근 권한이 제한되지 않습니다."
    if custom_type == "X_FRAME_OPTIONS_CUSTOM":
        return "7-4", "취약한 보안설정", "일반", "X-Frame-Options 헤더가 누락되어 Clickjacking 공격에 노출될 수 있습니다."
    if custom_type == "HSTS_CUSTOM":
        return "7-4", "취약한 보안설정", "일반", "Strict-Transport-Security 헤더가 누락되어 HTTP 다운그레이드 공격에 취약합니다."
    if custom_type == "6-1_ERR_DISCLOSE":
        return "6-1", "오류페이지를 통한 정보 노출 여부", "일반", "에러 응답에 Spring Boot 내부 패키지 구조 및 Java 예외 정보가 노출되어 공격자에게 서버 내부 구조를 알려줄 수 있습니다."

    if any(k in an for k in ["cross-site", "cross site", "xss", "csrf", "크로스", "스크립팅"]):
        return "1-1", "XSS / CSRF 공격 가능성", "중요", "사용자 입력값이 출력 혹은 다른 사이트의 권한 요청으로 그대로 전송되어 악성 스크립트 실행이나 세션 오용 우려가 존재합니다."
    if any(k in an for k in ["sql injection", "xml", "xpath", "ldap", "인젝션", "삽입"]):
        return "1-2", "삽입(Injection) 공격 가능성", "중요", "데이터베이스 질의문이나 XML 파서 등에 검증되지 않은 쿼리 예약어 조작 값이 입력되어 내부 데이터를 무단으로 탈출하거나 위조할 수 있습니다."
    if any(k in an for k in ["fuzz", "parameter tampering", "tamper", "퍼저", "조작"]):
        return "1-3", "파라미터 값 및 히든(Hidden) 필드 조작 가능성", "중요", "요청 파라미터나 비공개 헤더 정보의 경계값을 임의 변조하여 비정상 예외 또는 통제되지 않은 결과 처리를 유도할 수 있습니다."
    if any(k in an for k in ["server-side request forgery", "ssrf", "file inclusion", "포함"]):
        return "1-4", "SSRF / File Inclusion 공격 가능성", "중요", "서버가 외부의 임의 리소스에 대신 요청하게 하거나 로컬/원격 파일을 강제로 첨부 실행시키도록 공격 매개변수를 악용할 수 있습니다."
    if any(k in an for k in ["redirect", "forward", "리다이렉트", "포워드"]):
        return "1-5", "검증되지 않은 리다이렉트와 포워드", "일반", "검증되지 않은 피싱용 외부 사이트로 사용자 브라우저 화면이 자동 전환되는 위험성입니다."
    if any(k in an or k in desc for k in ["buffer", "overflow", "format string", "버퍼", "오버플로우", "포맷 스트링"]):
        return "1-6", "입력 값 크기 및 무결성 검증 오류", "중요", "서버 버퍼 메모리 크기를 초과하는 데이터 유입 시 메모리 오류나 비정상 크래시를 발생시키는 원인입니다."

    if any(k in an or k in desc for k in ["upload", "업로드"]):
        return "2-1", "악성코드파일 업로드", "중요", "파일 업로드 경로에 실행 가능한 웹쉘 등의 확장자 및 스크립트 검증 필터링이 부재합니다."
    if any(k in an or k in desc for k in ["directory browsing", "download", "디렉터리", "디렉토리", "목록화", "다운로드"]):
        return "2-2", "중요 정보 파일 다운로드 가능성", "중요", "상위 디렉토리 참조 기법 등을 활용해 시스템 비공개 파일이나 설정 파일을 무단 다운로드할 위험입니다."

    if any(k in an for k in ["password", "credential", "패스워드", "비밀번호"]):
        return "3-1", "패스워드 정책 유무 및 반영 여부", "일반", "비밀번호 안전 복잡도 검사나 무작위 대입 차단 수준이 미흡합니다."
    if any(k in an for k in ["brute force", "lockout", "무작위", "대입"]):
        return "3-2", "인증 실패 횟수 제한", "일반", "단시간 내에 수많은 비밀번호 대입 시도가 발생할 때 자동 잠금이나 캡차 보호 처리가 미흡합니다."
    if any(k in an for k in ["username enumeration", "user enumeration", "열거"]):
        return "3-3", "계정 정보 파악 가능성", "일반", "회원가입/로그인 시도 에러 메시지를 통해 특정 계정의 존재 여부를 해커가 한눈에 추론할 수 있게 유출되는 취약점입니다."
    if any(k in desc or k in an for k in ["admin", "관리자"]):
        return "3-4", "관리자 페이지 분리 여부", "일반", "외부 인터넷 망에 관리자 로그인 기능이나 전용 API 콘솔 주소가 그대로 노출되어 있습니다."
    if any(k in pn or k in an or k in desc for k in ["user-agent", "user agent", "robotic", "유저 에이전트"]):
        return "3-5", "검색엔진 정보 노출 가능성", "일반", "유저 에이전트(User-Agent) 변조 접속을 활용하여 일반 브라우저 외에 다양한 웹 검색 로봇(봇) 우회 및 데이터 크롤링을 허용하는 상태입니다."
    if any(k in an for k in ["backup", "temp file", "백업", "임시"]):
        return "3-6", "백업 파일 및 테스트 파일 존재 여부", "일반", "서버 루트 경로에 임시 저장된 .bak, .tmp, .zip 백업 소스코드 등이 방치되어 다운로드 가능한 위험성입니다."

    if any(k in an for k in ["samesite", "cookie", "쿠키", "storage", "스토리지"]):
        return "4-1", "쿠키(Cookie) 및 웹 스토리지(Web Storage) 조작 가능성", "일반", "쿠키 생성 시 SameSite, Secure, HttpOnly 속성이 누락되어 CSRF나 세션 갈취(XSS) 공격에 취약해집니다."
    if any(k in an for k in ["session", "token", "jwt", "세션", "토큰"]):
        return "4-2", "인증(세션 및 토큰) 값 안전성 설정 여부", "일반", "JWT 토큰 서명 키가 단순하거나 만료 시간 제한이 너무 길어 인증 무효화 처리가 미비합니다."
    if any(k in an for k in ["bypass", "access control", "우회", "접근제어"]):
        return "4-3", "접근제어 우회 가능성 확인", "일반", "특정 헤더 변조나 HTTP 메소드(GET->POST 우회 등)의 변경을 통해 접근 통제 처리를 우회할 수 있는 취약성입니다."
    if any(k in an for k in ["unauthorized", "missing authorization", "인가", "인증 누락"]):
        return "4-4", "비인증 상태로 중요 page접근 가능성", "일반", "토큰 없이도 회원 권한이나 예약 생성 등 주요 데이터 변경 API에 접근할 수 있는지 여부입니다."
    if any(k in an for k in ["privilege", "escalation", "권한 상승"]):
        return "4-5", "일반계정 권한 상승 가능성", "일반", "일반 유저 권한의 토큰으로 관리자(ADMIN) 권한의 자원을 조작하거나 다른 판매자의 재고 정보를 수정할 수 있는 수평적/수직적 권한 변조 우려입니다."

    if any(k in an or k in desc for k in ["source code", "소스 코드"]):
        return "5-1", "소스코드 내 주요정보 노출 여부", "일반", "클라이언트용 자바스크립트나 HTML 페이지 주석 내에 비밀번호, API 키, 주석 등이 고스란히 유출되고 있습니다."
    if any(k in an or k in desc or k in pn for k in ["sensitive", "pii", "personal", "userId", "개인 정보", "민감"]):
        return "5-2", "요청 및 응답 값 내 주요정보 포함여부 확인", "중요", "주민번호, 비밀번호, 결제 정보, 사용자 식별자(ID) 등이 암호화 없이 전송되거나 URL 주소창에 고스란히 남아 있는 구조입니다."

    if any(k in an for k in ["error", "disclosure", "오류", "노출", "error disclosure"]):
        return "6-1", "오류페이지를 통한 정보 노출 여부", "일반", "비정상 파라미터 입력 시 서버 시스템 에러 화면이나 프레임워크 스택 트레이스 정보가 사용자 응답에 노출되는 상태입니다."
    if any(k in desc for k in ["generic error", "error page"]):
        return "6-2", "일괄적인 오류 처리 페이지 존재 여부", "일반", "모든 예외 상황을 공통 에러 핸들러로 깔끔하게 정리하지 않고 시스템 기본 예외 응답을 노출하고 있습니다."

    if any(k in an or k in desc for k in ["method", "http method"]):
        return "7-1", "Client Request Method", "일반", "사용하지 않는 HTTP Method(OPTIONS, TRACE, PUT, DELETE)가 외부로 지나치게 허용되고 있습니다."
    if any(k in an for k in ["indexing", "directory listing"]):
        return "7-2", "파일 목록화 가능성", "일반", "서버 자원 주소 뒤에 슬래시(/)를 붙였을 때 폴더 내부 구조가 리스트업되어 노출될 위험입니다."
    if any(k in an for k in ["header", "banner", "헤더", "배너"]):
        return "7-3", "서버 헤더정보 노출", "일반", "HTTP 응답 헤더 내에 서버 운영체제 정보나 웹 서버 엔진 버전(Nginx, Apache 등)이 노출되고 있습니다."
    if any(k in an for k in ["security header", "x-content"]):
        return "7-4", "취약한 보안설정", "일반", "웹 브라우저 보안 헤더(X-Frame-Options, X-Content-Type-Options 등) 누락으로 인한 위험입니다."

    return "8-1", "취약점 진단 항목에 정의되지 않은 취약점", "-", "기타 정의되지 않은 시스템 정보 수집 공격에 해당합니다."

# 취약점 ID 및 유형별 한글 설명 및 실제 조치 코드 템플릿 매핑
KOREAN_REMEDIATIONS = {
    "40012": { # Reflected XSS
        "summary": "입력값 검증 및 인코딩 미흡으로 인한 반사형 XSS 취약점입니다.",
        "cause": "요청 파라미터(예: {param})에 악성 스크립트가 입력되었을 때, 서버가 이를 필터링하지 않고 응답 결과로 그대로 출력하여 브라우저에서 스크립트가 실행될 수 있습니다.",
        "action_guide": (
            "1. 입력값 필터링: Spring Boot 환경인 경우 XssEscapeServletFilter 같은 서블릿 필터를 적용하여 요청 파라미터의 HTML 특수문자(<, >, &, \")를 인코딩 처리하세요.\n"
            "2. 응답 헤더 추가: 응답 헤더에 'X-Content-Type-Options: nosniff'를 추가하여 브라우저가 응답 데이터를 HTML로 오인하여 실행하지 않도록 설정하세요."
        ),
        "code_example": (
            "// Spring Boot XSS 필터 적용 예시 (Lucy XSS Filter)\n"
            "@Configuration\n"
            "public class XssConfig implements WebMvcConfigurer {\n"
            "    @Bean\n"
            "    public FilterRegistrationBean<XssEscapeServletFilter> getFilterRegistrationBean() {\n"
            "        FilterRegistrationBean<XssEscapeServletFilter> registrationBean = new FilterRegistrationBean<>();\n"
            "        registrationBean.setFilter(new XssEscapeServletFilter());\n"
            "        registrationBean.setOrder(1);\n"
            "        registrationBean.addUrlPatterns(\"/*\");\n"
            "        return registrationBean;\n"
            "    }\n"
            "}"
        )
    },
    "40014": { # Persistent XSS
        "summary": "데이터베이스 저장값 출력 과정에서 발생하는 지속성 XSS 취약점입니다.",
        "cause": "데이터베이스에 저장된 악성 페이로드가 화면 렌더링 시 여과 없이 텍스트가 아닌 HTML 태그로 해석되어 실행되는 위협입니다.",
        "action_guide": "데이터 저장 및 조회 시점에 HTML 엔티티 인코딩(HtmlUtils.htmlEscape)을 필수 적용하고, 부득이하게 Rich Text Editor를 쓰는 경우 Naver Lucy Sanitizer 등으로 위험 태그만 걸러내는 화이트리스트 필터를 거치도록 수정하세요.",
        "code_example": "String safeContent = HtmlUtils.htmlEscape(userData.getContent());"
    },
    "DOM_XSS_CUSTOM": {
        "summary": "클라이언트 측 DOM 삽입 지점을 이용한 DOM 기반 XSS 취약점입니다.",
        "cause": "브라우저의 DOM API가 사용자 입력을 그대로 HTML/JavaScript로 해석하여 악성 스크립트를 실행시킬 수 있습니다.",
        "action_guide": "document.write, innerHTML, outerHTML 같은 DOM 삽입 API 사용을 줄이고, 안전한 텍스트 노드 삽입이나 적절한 인코딩/화이트리스트 필터를 적용하세요.",
        "code_example": "element.textContent = userInput;"
    },
    "40018": { # SQL Injection
        "summary": "동적 SQL 쿼리 구성으로 인한 SQL 인젝션 취약점입니다.",
        "cause": "사용자 입력값이 SQL 쿼리 문자열에 직접 결합되어(Statement 방식), 데이터베이스 구조 조작이나 인증 우회 공격에 노출됩니다.",
        "action_guide": "MyBatis 사용 시 '$' 대신 '#' 기호를 사용하여 Prepared Statement 파라미터 바인딩을 적용하고, JPA 사용 시 동적 쿼리에 대해 JPQL 파라미터 바인딩을 필히 적용하세요.",
        "code_example": (
            "<!-- MyBatis 해결 예시 -->\n"
            "<!-- 취약한 코드: SELECT * FROM users WHERE id = '${userId}' -->\n"
            "<!-- 안전한 코드: -->\n"
            "SELECT * FROM users WHERE id = #{userId}"
        )
    },
    "CSRF_CUSTOM": {
        "summary": "안전하지 않은 쿠키 세션 처리로 인한 CSRF(요청 위조) 취약점입니다.",
        "cause": "Authorization 헤더가 없어도 브라우저에 저장된 accessToken 쿠키의 자동 전송을 허용하며, CORS 설정에서 외부 Origin의 신용정보(Credentials) 전송을 수락하고 있습니다.",
        "action_guide": (
            "1. 쿠키 발급 시 SameSite 속성을 'Lax' 또는 'Strict'로 지정하세요.\n"
            "2. 중요 쓰기 작업 API는 쿠키 인증 대신 HTTP Authorization Header 방식의 Bearer 토큰 검증만 허용하도록 백엔드 시큐리티 설정을 변경하세요."
        ),
        "code_example": (
            "// Spring Boot Cookie 발급 시 SameSite 설정 예시\n"
            "ResponseCookie cookie = ResponseCookie.from(\"accessToken\", token)\n"
            "        .httpOnly(true)\n"
            "        .secure(true)\n"
            "        .path(\"/\")\n"
            "        .maxAge(3600)\n"
            "        .sameSite(\"Lax\") // CSRF 방어 핵심\n"
            "        .build();\n"
            "response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());"
        )
    },
    "90034": {
        "summary": "HTML Form 내 Anti-CSRF 토큰 부재 취약점입니다.",
        "cause": "서버가 브라우저 사용자로부터의 요청을 받을 때, 세션 상태를 검증하기 위한 무작위 일회성 CSRF 토큰 검증 절차가 누락되어 있습니다.",
        "action_guide": (
            "1. Spring Security 환경인 경우 CSRF 보호 필터를 기본 활성화(http.csrf(withDefaults())) 처리하세요.\n"
            "2. 클라이언트와 서버가 완전 무상태 API(Stateless) 형태로 통신하는 경우, 요청 주체가 쿠키 인증을 사용하지 않고 헤더(Authorization) 기반 Bearer 토큰만 사용하도록 변경하는 것으로 조치 가능합니다."
        ),
        "code_example": (
            "// Spring Security CSRF 보호 기본 설정 예시\n"
            "@Bean\n"
            "public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
            "    http.csrf(csrf -> csrf.ignoringRequestMatchers(\"/api/v1/auth/login\")); // 필요한 비인가 엔드포인트만 예외 지정\n"
            "    return http.build();\n"
            "}"
        )
    },
    "MIME_SNIFF_CUSTOM": {
        "summary": "MIME 스니핑 방지 헤더 누락 취약점입니다.",
        "cause": "API 응답에 'X-Content-Type-Options: nosniff' 헤더가 누락되어 있습니다. 브라우저가 JSON 형식을 HTML이나 스크립트로 임의로 속성 해석(Sniffing)하여 악의적인 스크립트를 렌더링시킬 수 있습니다.",
        "action_guide": "웹 서버 설정(Nginx 등)이나 백엔드 Security Filter 단계에서 'X-Content-Type-Options: nosniff' 헤더를 항상 포함하여 응답하도록 보완하세요.",
        "code_example": (
            "// Spring Security 기본적으로 작동하나 수동 설정 시:\n"
            "http.headers(headers -> headers.contentTypeOptions(configs -> configs.disable().and().defaultsDisabled())); // 혹은 기본 활성화 유지"
        )
    },
    "REFERRER_POLICY_CUSTOM": {
        "summary": "Referrer-Policy 보안 헤더 누락 취약점입니다.",
        "cause": "응답 헤더에 'Referrer-Policy'가 설정되어 있지 않아, 다른 도메인으로 이동 시 내부 API 요청 URL 정보(민감 파라미터나 토큰 등)가 Referer 요청 헤더를 통해 유출될 수 있습니다.",
        "action_guide": "Referer 헤더 전송 수준을 통제할 수 있도록 'Referrer-Policy: no-referrer' 또는 'strict-origin-when-cross-origin'을 응답에 설정하세요.",
        "code_example": (
            "// Nginx 설정 예시\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
        )
    },
    "PERMISSIONS_POLICY_CUSTOM": {
        "summary": "Permissions-Policy 보안 헤더 누락 취약점입니다.",
        "cause": "Permissions-Policy 헤더가 부재하여, 브라우저가 지원하는 강력한 하드웨어 API(카메라, 마이크, 위치 정보 등)의 허용 권한 제어가 크로스 사이트 context에서 엄격하게 차단되지 않습니다.",
        "action_guide": "사용하지 않는 브라우저 기능 권한을 기본적으로 거부(deny) 처리하는 Permissions-Policy 헤더를 구성하세요.",
        "code_example": (
            "// Nginx 설정 예시\n"
            "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;"
        )
    },
    "X_FRAME_OPTIONS_CUSTOM": {
        "summary": "클릭재킹 방지용 X-Frame-Options 헤더 누락 취약점입니다.",
        "cause": "X-Frame-Options 헤더가 설정되어 있지 않거나 미흡하여, 공격자가 악의적인 사이트 내부 iframe 태그에 본 서비스를 내장시켜 사용자 오클릭을 유도(Clickjacking)할 위험이 있습니다.",
        "action_guide": "응답 헤더에 'X-Frame-Options: DENY' 또는 'SAMEORIGIN' 속성을 활성화하세요.",
        "code_example": (
            "// Spring Security 설정 예시\n"
            "http.headers(headers -> headers.frameOptions(options -> options.deny()));"
        )
    },
    "HSTS_CUSTOM": {
        "summary": "HTTP Strict-Transport-Security (HSTS) 헤더 누락 취약점입니다.",
        "cause": "HTTPS 환경임에도 HSTS 헤더가 활성화되어 있지 않아, 사용자가 최초 접속 혹은 특정 시점에 강제로 HTTP 경로로 강제 우회되어 중간자 공격(MitM)을 당할 여지가 있습니다.",
        "action_guide": "브라우저에게 일정 기간 HTTPS 통신만 강제하도록 강제하는 'Strict-Transport-Security: max-age=31536000; includeSubDomains'를 추가하세요.",
        "code_example": (
            "// Nginx SSL 가이드 예시\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        )
    },
    "CORS_ORIGIN_REFLECTION": {
        "summary": "CORS Origin Reflection 취약점으로, 임의 도메인에서 인증된 API 요청이 가능합니다.",
        "cause": "서버가 Access-Control-Allow-Origin 헤더를 고정값으로 설정하지 않고, 클라이언트가 전송한 Origin 헤더값을 그대로 반사합니다. 동시에 Access-Control-Allow-Credentials: true가 설정되어 있어 공격 도메인에서 희생자의 브라우저 세션 쿠키를 이용한 API 접근이 가능합니다.",
        "action_guide": (
            "1. allowedOrigins를 신뢰 도메인 화이트리스트로 고정하세요 (와일드카드 * 사용 금지).\n"
            "2. Credentials를 허용해야 하는 경우, ALLOWED_ORIGINS 목록을 엄격히 관리하고 동적 반사를 제거하세요.\n"
            "3. Spring Security에서 CorsConfiguration.setAllowedOrigins()에 명시적 도메인만 지정하세요."
        ),
        "code_example": (
            "// Spring Boot CORS 화이트리스트 고정 예시\n"
            "@Bean\n"
            "public CorsFilter corsFilter() {\n"
            "    CorsConfiguration config = new CorsConfiguration();\n"
            "    config.setAllowedOrigins(List.of(\"https://trusted.example.com\")); // 반사 금지\n"
            "    config.setAllowCredentials(true);\n"
            "    config.setAllowedMethods(List.of(\"GET\", \"POST\", \"PUT\", \"DELETE\"));\n"
            "    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();\n"
            "    source.registerCorsConfiguration(\"/**\", config);\n"
            "    return new CorsFilter(source);\n"
            "}"
        )
    },
    "6-1_ERR_DISCLOSE": {
        "summary": "에러 응답에 서버 내부 구조 정보가 노출되는 취약점입니다.",
        "cause": "Spring Boot가 예외 처리 시 systemMessage 필드에 Java 패키지명, 클래스명, 예외 타입 등 내부 구조 정보를 그대로 출력하고 있습니다. 공격자가 이를 통해 서버 기술 스택과 데이터 모델 구조를 파악하여 보다 정교한 공격을 설계할 수 있습니다.",
        "action_guide": (
            "1. 운영 환경에서는 에러 응답의 systemMessage 필드를 제거하거나 고정 메시지로 대체하세요.\n"
            "2. Spring Boot application.properties에서 'server.error.include-message=never' 설정을 적용하세요.\n"
            "3. @ControllerAdvice + @ExceptionHandler로 전역 예외 처리를 구현하여 내부 정보가 포함되지 않은 표준 에러 응답만 반환하세요."
        ),
        "code_example": (
            "// Spring Boot 전역 예외 처리 예시\n"
            "@RestControllerAdvice\n"
            "public class GlobalExceptionHandler {\n"
            "    @ExceptionHandler(Exception.class)\n"
            "    public ResponseEntity<ErrorResponse> handleException(Exception e) {\n"
            "        // 내부 예외 정보는 서버 로그에만 기록\n"
            "        log.error(\"Internal error\", e);\n"
            "        // 클라이언트에는 고정 메시지만 반환\n"
            "        return ResponseEntity.status(500)\n"
            "            .body(new ErrorResponse(\"서버 내부 오류가 발생했습니다.\"));\n"
            "    }\n"
            "}"
        )
    }
}

# ── 다중 XSS 페이로드 목록 (WAF/필터 우회 변형 포함) ───────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<scrIpt>alert(1);</scrIpt>",
    "<img src=x onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",                  # 슬래시 우회
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",               # HTML5 이벤트 핸들러
    "<body onload=alert(1)>",
    "<!--<img src=--><img src=x onerror=alert(1)//>",  # 주석 우회
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

# ── 반사 지점(Context)별 2차 정밀 검증용 페이로드 사전 ────────────────────────────────────
CONTEXT_PAYLOADS = {
    "HTML body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    "HTML attribute": [
        "\" onmouseover=alert(1) x=\"",
        "' onmouseover=alert(1) x='",
        "\" autofocus onfocus=alert(1) x=\""
    ],
    "JSON/String value": [
        "</script><script>alert(1)</script>",
        "\\\"+alert(1)+\\\"",
        "<img src=x onerror=alert(1)>"
    ],
    "encoded/reflected": [
        "<script>alert(1)</script>",
        "%3Cscript%3Ealert(1)%3C/script%3E"
    ],
}
def resolve_schema_ref(schema: dict, components: dict | None = None) -> dict:
    if not isinstance(schema, dict):
        return schema
    ref = schema.get("$ref")
    if not ref or not components:
        return schema
    if not ref.startswith("#/components/schemas/"):
        return schema
    schema_name = ref.rsplit("/", 1)[-1]
    return components.get("schemas", {}).get(schema_name, schema)

def extract_injectable_keypaths(schema: dict, prefix: str = "", components: dict | None = None) -> list[str]:
    """JSON 스키마를 재귀적으로 탐색하여 string 타입의 모든 키 경로(Dot-notation)를 추출합니다."""
    schema = resolve_schema_ref(schema, components)
    paths = []
    if not isinstance(schema, dict):
        return paths

    # properties 탐색
    properties = schema.get("properties", {})
    for k, v in properties.items():
        full_key = f"{prefix}.{k}" if prefix else k
        v = resolve_schema_ref(v, components)
        p_type = get_schema_type(v, components)
        
        if is_xss_injectable_schema(v, k, components):
            paths.append(full_key)
        elif p_type == "object":
            paths.extend(extract_injectable_keypaths(v, full_key, components))
        elif p_type == "array":
            # 배열 내 아이템이 객체인 경우 처리
            items_schema = resolve_schema_ref(v.get("items", {}), components)
            if isinstance(items_schema, dict) and get_schema_type(items_schema, components) == "object":
                paths.extend(extract_injectable_keypaths(items_schema, f"{full_key}.0", components))
    return paths

def schema_for_keypath(schema: dict, keypath: str, components: dict | None = None) -> dict:
    current = resolve_schema_ref(schema, components)
    for part in str(keypath or "").split("."):
        if not isinstance(current, dict):
            return {}
        current = resolve_schema_ref(current, components)
        if part.isdigit():
            current = resolve_schema_ref(current.get("items", {}), components)
            continue
        if get_schema_type(current, components) == "array":
            current = resolve_schema_ref(current.get("items", {}), components)
        properties = current.get("properties", {}) if isinstance(current, dict) else {}
        current = resolve_schema_ref(properties.get(part, {}), components)
    return current if isinstance(current, dict) else {}

def set_nested_value_by_keypath(target_dict: dict, keypath: str, value: any) -> dict:
    """점(.)으로 구분된 키 경로에 맞춰 중첩 딕셔너리에 값을 대입합니다."""
    parts = keypath.split(".")
    curr = target_dict
    for idx, part in enumerate(parts[:-1]):
        next_part = parts[idx + 1]
        if isinstance(curr, list):
            list_idx = int(part)
            while len(curr) <= list_idx:
                curr.append({} if not next_part.isdigit() else [])
            curr = curr[list_idx]
            continue
        if part not in curr or not isinstance(curr[part], (dict, list)):
            curr[part] = [] if next_part.isdigit() else {}
        curr = curr[part]
    last = parts[-1]
    if isinstance(curr, list):
        list_idx = int(last)
        while len(curr) <= list_idx:
            curr.append(None)
        curr[list_idx] = value
    else:
        curr[last] = value
    return target_dict

def get_schema_type(schema: dict, components: dict | None = None) -> str:
    schema = resolve_schema_ref(schema, components)
    if not isinstance(schema, dict):
        return "unknown"
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return next((t for t in schema_type if t != "null"), "unknown")
    if schema_type:
        return schema_type
    for key in ["oneOf", "anyOf", "allOf"]:
        variants = schema.get(key)
        if isinstance(variants, list) and variants:
            return get_schema_type(variants[0], components)
    return "unknown"

def normalized_field_name(param_name: str = "") -> str:
    return re.sub(r"[^a-z0-9]", "", str(param_name or "").lower())

def is_sensitive_or_nontext_field(param_name: str = "") -> bool:
    pn = normalized_field_name(param_name)
    sensitive_tokens = [
        "password", "passwd", "pwd", "secret", "token", "accesstoken", "refreshtoken",
        "authorization", "auth", "otp", "verificationcode", "emailcode", "csrf",
        "session", "cookie", "credential", "key",
    ]
    strict_tokens = [
        "phone", "tel", "mobile", "zipcode", "postcode", "birth",
        "uuid", "number", "count", "amount", "price", "rate", "capacity",
    ]
    if any(token in pn for token in sensitive_tokens + strict_tokens):
        return True
    if pn in {"id", "ids"} or pn.endswith("id") or pn.endswith("ids"):
        return True
    if pn in {
        "date", "datetime", "time", "timestamp", "startdate", "enddate",
        "createdat", "updatedat", "deletedat", "openedat", "closedat",
        "birthdate", "birthtime",
    }:
        return True
    return False

def is_xss_injectable_schema(schema: dict, param_name: str = "", components: dict | None = None) -> bool:
    schema = resolve_schema_ref(schema, components)
    if not schema and param_name and not is_sensitive_or_nontext_field(param_name):
        schema = {"type": "string"}
    if not isinstance(schema, dict):
        return False
    if is_sensitive_or_nontext_field(param_name):
        return False
    if schema.get("enum"):
        return False
    if get_schema_type(schema, components) != "string":
        return False
    if (schema.get("format") or "").lower() in {"date", "date-time", "byte", "binary", "uuid"}:
        return False
    return True

def looks_like_file_field(param_name: str = "", schema: dict | None = None, components: dict | None = None) -> bool:
    schema = resolve_schema_ref(schema or {}, components)
    prop_type = get_schema_type(schema, components)
    prop_format = (schema.get("format") or "").lower() if isinstance(schema, dict) else ""
    items_schema = resolve_schema_ref(schema.get("items", {}), components) if isinstance(schema, dict) else {}
    item_format = (items_schema.get("format") or "").lower() if isinstance(items_schema, dict) else ""
    if prop_type == "string" and prop_format == "binary":
        return True
    if prop_type == "array" and item_format == "binary":
        return True
    field = normalized_field_name(param_name)
    return any(token in field for token in ["image", "images", "photo", "photos", "file", "files", "upload", "attachment"])

def payloads_for_xss_field(param_name: str = "", schema: dict | None = None, components: dict | None = None) -> list:
    schema = resolve_schema_ref(schema or {}, components)
    if not schema and param_name and not is_sensitive_or_nontext_field(param_name):
        schema = {"type": "string"}
    fmt = (schema.get("format") or "").lower() if isinstance(schema, dict) else ""
    pn = normalized_field_name(param_name)

    if is_sensitive_or_nontext_field(param_name):
        return []
    if fmt == "email" or "email" in pn:
        return [
            '"xss<img src=x onerror=alert(1)>"@example.com',
            '"xss<script>alert(1)</script>"@example.com',
        ]
    if any(token in pn for token in ["url", "uri", "link", "homepage", "website", "redirect"]):
        return [
            "javascript:alert(1)",
            "https://example.com/%3Cscript%3Ealert(1)%3C/script%3E",
            "https://example.com/\"><script>alert(1)</script>",
        ]
    return XSS_PAYLOADS

def make_unique_xss_payload(base_payload: str, param_name: str = "") -> str:
    marker_source = f"{param_name}:{time.time_ns()}:{base_payload}"
    marker_hash = hashlib.sha1(marker_source.encode("utf-8", errors="ignore")).hexdigest()[:10]
    safe_param = re.sub(r"[^A-Za-z0-9_]", "_", str(param_name or "field"))[:24] or "field"
    marker = f"ARGUS_{safe_param}_{marker_hash}"

    replacements = [
        ("alert(1)", f"alert('{marker}')"),
        ("alert(1);", f"alert('{marker}');"),
    ]
    for old, new in replacements:
        if old in base_payload:
            return base_payload.replace(old, new)
    if "javascript:" in base_payload.lower():
        return f"javascript:alert('{marker}')"
    return f"<img src=x onerror=alert('{marker}')>"

def looks_like_validation_rejection(response) -> bool:
    if response is None or response.status_code != 400:
        return False
    text = (getattr(response, "text", "") or "").lower()
    validation_markers = [
        "valid", "validation", "fielderror", "field_errors", "fielderrors",
        "invalid", "format", "constraint", "입력값", "형식", "올바르지",
        "검증", "유효", "비밀번호", "이메일", "전화번호", "닉네임",
    ]
    return any(marker in text for marker in validation_markers)

def default_value_for_schema(schema: dict, components: dict | None = None, param_name: str = ""):
    schema = resolve_schema_ref(schema, components)
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]

    schema_type = get_schema_type(schema, components)
    fmt = (schema.get("format", "") or "").lower()
    pn = normalized_field_name(param_name)
    if schema_type == "integer":
        minimum = schema.get("minimum")
        if minimum is None:
            minimum = schema.get("min")
        try:
            value = int(minimum) if minimum is not None else 1
        except Exception:
            value = 1
        if schema.get("exclusiveMinimum") is True:
            value += 1
        if any(token in pn for token in ["recruitcount", "membercount", "capacity", "personnel", "peoplecount", "guest"]):
            value = max(value, 2)
        return value
    if schema_type == "number":
        minimum = schema.get("minimum")
        try:
            value = float(minimum) if minimum is not None else 1.0
        except Exception:
            value = 1.0
        if schema.get("exclusiveMinimum") is True:
            value += 1.0
        return value
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        item_default = default_value_for_schema(schema.get("items", {}), components, param_name)
        return [item_default] if item_default is not None else []
    if schema_type == "object":
        return build_default_payload_from_schema(schema, components)
    if fmt == "date" or any(token in pn for token in ["enddate", "duedate", "deadline", "closedate", "checkout"]):
        days = 30 if any(token in pn for token in ["enddate", "duedate", "deadline", "closedate", "checkout"]) else 1
        return (date.today() + timedelta(days=days)).isoformat()
    if fmt == "date-time":
        return (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if schema_type == "unknown":
        return None

    if "email" in pn:
        return "fuzz-test@example.com"
    if "password" in pn or "pwd" in pn:
        return "SecurePass123!"
    if any(token in pn for token in ["phone", "tel", "mobile", "contact"]):
        return "010-1234-5678"
    if "nickname" in pn:
        return "safeNickname"
    if "representative" in pn or "holder" in pn:
        return "HongGildong"
    if "businessnumber" in pn or "accountnumber" in pn or "business_number" in pn or "account_number" in pn:
        return "1234567890"
    if any(token in pn for token in ["startdate", "checkin"]):
        return (date.today() + timedelta(days=1)).isoformat()
    if "category" in pn:
        return "GENERAL"

    min_len = schema.get("minLength") or schema.get("min_length") or 0
    try:
        min_len = int(min_len)
    except Exception:
        min_len = 0
    value = "safe"
    if min_len > len(value):
        value = value + ("x" * (min_len - len(value)))

    max_len = schema.get("maxLength") or schema.get("max_length")
    try:
        if max_len is not None and len(value) > int(max_len):
            value = value[:int(max_len)]
    except Exception:
        pass
    return value

def default_value_for_query_param(param_name: str, schema: dict, components: dict | None = None):
    if get_schema_type(schema, components) in {"object", "array", "unknown"}:
        return None
    return default_value_for_schema(schema, components, param_name)

def build_default_payload_from_schema(schema: dict, components: dict | None = None) -> dict:
    schema = resolve_schema_ref(schema, components)
    payload = {}
    if not isinstance(schema, dict):
        return payload
    for key, prop_schema in schema.get("properties", {}).items():
        default_value = default_value_for_schema(prop_schema, components, key)
        if default_value is not None:
            payload[key] = default_value
    return payload

def build_required_payload_from_schema(schema: dict, components: dict | None = None) -> dict:
    schema = resolve_schema_ref(schema, components)
    payload = {}
    if not isinstance(schema, dict):
        return payload
    required = set(schema.get("required") or [])
    for key, prop_schema in (schema.get("properties") or {}).items():
        if key not in required:
            continue
        default_value = default_value_for_schema(prop_schema, components, key)
        if default_value is not None:
            payload[key] = default_value
    return payload

def build_query_defaults_from_details(details: dict | None, components: dict | None = None) -> dict:
    params = {}
    for param in (details or {}).get("parameters", []) or []:
        if not isinstance(param, dict) or str(param.get("in") or "query").lower() != "query":
            continue
        name = param.get("name")
        if not name:
            continue
        schema = dict(param.get("schema") or {})
        for sample_key in ("example", "default", "sample"):
            if param.get(sample_key) not in (None, "") and sample_key not in schema:
                schema["example" if sample_key == "sample" else sample_key] = param.get(sample_key)
                break
        default_value = default_value_for_query_param(name, schema, components)
        if default_value is not None:
            params[name] = default_value
    return params

def find_get_endpoint_for_post(post_path: str, validated_endpoints: dict) -> str | None:
    """POST 엔드포인트 경로에 대응하는 GET 단건 조회 엔드포인트를 Swagger 목록에서 탐색합니다.
    
    예: POST /api/v1/posts → GET /api/v1/posts/{id}
    반환값이 None이면 대응 GET 엔드포인트를 찾지 못한 것.
    """
    for ep_path, ep_methods in validated_endpoints.items():
        if "get" not in ep_methods:
            continue
        # POST 경로가 GET 경로의 prefix이고 GET 경로에 경로 변수({...})가 있는 패턴 탐색
        if ep_path.startswith(post_path.rstrip("/")) and "{" in ep_path:
            return ep_path
    return None

def find_readable_endpoints_for_post(post_path: str, validated_endpoints: dict) -> list[tuple[str, str]]:
    candidates = []
    normalized_post_path = post_path.rstrip("/")

    for ep_path, ep_methods in validated_endpoints.items():
        if "get" not in ep_methods:
            continue

        normalized_ep_path = ep_path.rstrip("/")
        if normalized_ep_path == normalized_post_path:
            candidates.append(("list", ep_path))
        elif normalized_ep_path.startswith(normalized_post_path) and "{" in ep_path:
            candidates.append(("single", ep_path))

    return candidates

def extract_id_from_response(resp_json, depth=0):
    if depth > 3:
        return None
    if isinstance(resp_json, dict):
        for key in ["id", "uuid", "key", "no", "seq"]:
            if key in resp_json and resp_json[key] is not None:
                return resp_json[key]
        for value in resp_json.values():
            result = extract_id_from_response(value, depth + 1)
            if result is not None:
                return result
    return None

def extract_id_from_url(url: str):
    try:
        path_value = urllib.parse.urlparse(url).path
    except Exception:
        path_value = str(url or "")
    for segment in reversed(path_value.strip("/").split("/")):
        if re.fullmatch(r"\d+", segment or ""):
            return segment
    return None

def extract_session_cookie_name(set_cookie_header: str) -> str | None:
    if not set_cookie_header:
        return None
    for part in set_cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name = part.split("=", 1)[0].strip()
            if any(k in name.lower() for k in ["token", "session", "auth", "jsessionid", "sid"]):
                return name
    return None

def check_csrf_token_absence(response):
    body = (getattr(response, "text", "") or "").lower()
    headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
    return not (
        "csrf" in body
        or "xsrf" in body
        or "x-csrf-token" in headers
        or "x-xsrf-token" in headers
    )

def build_cookie_header_from_account(account: dict | None) -> str:
    cookies = (account or {}).get("cookies") or {}
    if not isinstance(cookies, dict):
        return ""
    return "; ".join(f"{name}={value}" for name, value in cookies.items() if name and value is not None)

def build_normal_auth_headers(token: str | None = None, account: dict | None = None) -> dict:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {str(token).replace('Bearer ', '').strip()}"
    cookie_header = build_cookie_header_from_account(account)
    if cookie_header:
        headers["Cookie"] = cookie_header
    return headers

def build_auth_headers(token: str | None = None, account: dict | None = None, mode: str | None = None) -> dict:
    mode = (mode or (account or {}).get("auth_mode") or "both").lower()
    headers = {}

    if mode in {"header", "bearer", "both"} and token:
        headers["Authorization"] = f"Bearer {str(token).replace('Bearer ', '').strip()}"
    elif mode in {"authorization_raw", "raw"} and token:
        headers["Authorization"] = str(token).replace("Bearer ", "").strip()
    elif mode == "x_auth_token" and token:
        headers["X-Auth-Token"] = str(token).replace("Bearer ", "").strip()
    elif mode == "access_token_header" and token:
        headers["access-token"] = str(token).replace("Bearer ", "").strip()
    elif mode == "access_token_camel_header" and token:
        headers["accessToken"] = str(token).replace("Bearer ", "").strip()

    if mode in {"cookie", "both"}:
        cookie_header = build_cookie_header_from_account(account)
        if cookie_header:
            headers["Cookie"] = cookie_header

    return headers

def authorization_headers_from_account(account: dict, token: str | None = None) -> dict:
    current = dict(build_auth_headers(token or (account or {}).get("token"), account, (account or {}).get("auth_mode")))
    current.pop("Cookie", None)
    current.pop("cookie", None)
    if current:
        return current
    for mode in ["header", "authorization_raw", "x_auth_token", "access_token_header", "access_token_camel_header"]:
        headers = dict(build_auth_headers(token or (account or {}).get("token"), account, mode))
        headers.pop("Cookie", None)
        headers.pop("cookie", None)
        if headers:
            return headers
    return {}

def cookie_header_and_source(account: dict, token: str | None = None, fallback_cookie_name: str = "accessToken") -> tuple[str, str]:
    cookie_header = build_cookie_header_from_account(account)
    if cookie_header:
        return cookie_header, "real"
    clean_token = str(token or (account or {}).get("token") or "").replace("Bearer ", "").strip()
    if clean_token:
        cookie_name = str((account or {}).get("token_field") or fallback_cookie_name or "accessToken").split(".")[-1]
        return f"{cookie_name}={clean_token}", "synthetic"
    return "", "none"

def is_successful_auth_acceptance_status(status_code) -> bool:
    try:
        return 200 <= int(status_code or 0) < 400
    except Exception:
        return False

def classify_auth_acceptance(account: dict, protected_url: str, method: str, body=None, token: str | None = None, fallback_cookie_name: str = "accessToken") -> dict:
    authz_headers = authorization_headers_from_account(account, token)
    cookie_header, cookie_source = cookie_header_and_source(account, token, fallback_cookie_name)
    probes = {
        "no_auth": {},
        "header_only": dict(authz_headers),
        "cookie_only": {"Cookie": cookie_header} if cookie_header else {},
        "both": {**authz_headers, **({"Cookie": cookie_header} if cookie_header else {})},
    }
    statuses = {}
    errors = {}
    for name, headers in probes.items():
        try:
            res = requests.request(
                method=method.upper(),
                url=protected_url,
                json=body or {},
                headers=headers or None,
                timeout=4,
            )
            statuses[name] = res.status_code
        except Exception as exc:
            statuses[name] = None
            errors[name] = str(exc)

    def ok(name: str) -> bool:
        return is_successful_auth_acceptance_status(statuses.get(name))

    if ok("no_auth"):
        mode = "PUBLIC_OR_BROKEN"
    elif ok("header_only") and not ok("cookie_only"):
        mode = "HEADER_ONLY"
    elif ok("cookie_only") and not ok("header_only"):
        mode = "COOKIE_ONLY"
    elif ok("header_only") and ok("cookie_only"):
        mode = "HEADER_OR_COOKIE"
    elif ok("both") and not ok("header_only") and not ok("cookie_only"):
        mode = "HEADER_AND_COOKIE"
    else:
        mode = "UNKNOWN"
    result = {"mode": mode, "statuses": statuses, "cookie_source": cookie_source}
    if errors:
        result["errors"] = errors
    return result

def cookie_names_from_header(cookie_header: str) -> list:
    names = []
    for part in (cookie_header or "").split(";"):
        if "=" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names

def jwt_debug_summary(token: str | None) -> str:
    if not token:
        return "no-token"
    try:
        clean_token, payload = decode_jwt_claims(token)
        safe_claims = {
            key: payload.get(key)
            for key in ["sub", "auth", "role", "roles", "scope", "iss", "aud", "iat", "exp"]
            if key in payload
        }
        fingerprint = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()[:12]
        return f"fingerprint={fingerprint}, claims={safe_claims}"
    except Exception as exc:
        return f"jwt-debug-failed: {exc}"

def decode_jwt_claims(token: str | None) -> tuple[str, dict]:
    if not token:
        return "", {}
    clean_token = str(token).replace("Bearer ", "").strip()
    parts = clean_token.split(".")
    if len(parts) < 2:
        return clean_token, {}
    payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("utf-8")).decode("utf-8"))
    return clean_token, payload

def summarize_response_for_log(response, max_len: int = 180) -> str:
    if response is None:
        return ""
    try:
        data = response.json()
        if isinstance(data, dict):
            pieces = []
            error = data.get("error")
            if isinstance(error, dict) and error.get("code"):
                pieces.append(str(error.get("code")))
            for key in ["message", "error", "detail"]:
                value = data.get(key)
                if isinstance(value, str) and value:
                    pieces.append(value)
            if pieces:
                return " | ".join(pieces)[:max_len]
    except Exception:
        pass
    return ((getattr(response, "text", "") or "").replace("\n", " ").replace("\r", " "))[:max_len]

def has_unsafe_samesite_cookie(account: dict | None, response_set_cookie: str = "") -> bool:
    attrs = (account or {}).get("cookie_attrs") or {}
    if isinstance(attrs, dict) and attrs:
        for meta in attrs.values():
            samesite = ""
            if isinstance(meta, dict):
                samesite = str(meta.get("samesite") or "").lower()
            if samesite not in ["lax", "strict"]:
                return True
        return False

    lowered = (response_set_cookie or "").lower()
    if "samesite=lax" in lowered or "samesite=strict" in lowered:
        return False
    return True

def assess_security_headers(response, is_https=False):
    headers = response.headers
    checks = [
        ("X-Content-Type-Options", lambda v: "nosniff" in v.lower(), "X-Content-Type-Options header is missing or does not include nosniff."),
        ("X-Frame-Options", lambda v: v.lower() in ["deny", "sameorigin"], "X-Frame-Options header is missing or is not DENY/SAMEORIGIN."),
        ("Content-Security-Policy", lambda v: bool(v.strip()), "Content-Security-Policy header is missing."),
        ("Referrer-Policy", lambda v: bool(v.strip()), "Referrer-Policy header is missing."),
        ("Permissions-Policy", lambda v: bool(v.strip()), "Permissions-Policy header is missing."),
    ]
    if is_https:
        checks.append(("Strict-Transport-Security", lambda v: "max-age=" in v.lower(), "Strict-Transport-Security header is missing or invalid."))

    findings = []
    for header, validator, message in checks:
        actual = headers.get(header, "")
        if not actual or not validator(actual):
            findings.append({
                "header": header,
                "actual": actual,
                "message": message,
            })
    return findings


def detect_session_cookie(target_url: str, auth_token: str, validated_endpoints: dict = None) -> str:
    """Set-Cookie 헤더에서 세션 쿠키명(예: accessToken, JSESSIONID 등)을 자동으로 추출합니다.
    
    인증 유무나 CSRF 취약 여부 자체는 본 함수에서 판단하지 않고,
    이후 스캔 단계에서 이 쿠키만을 실어 요청을 재현하여 판단합니다.
    """
    if validated_endpoints:
        auth_paths = [
            p for p in validated_endpoints
            if any(k in p.lower() for k in ["auth", "login", "signin", "token", "oauth", "session"])
        ]
        probe_paths = auth_paths if auth_paths else list(validated_endpoints.keys())[:5]
    else:
        probe_paths = ["/api/v1/auth/login", "/api/v1/members/me", "/api/v1/posts", "/api/v1"]

    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    for path in probe_paths:
        try:
            res = requests.get(
                f"{target_url.rstrip('/')}{path}",
                headers=headers,
                timeout=3,
                allow_redirects=True,
            )
            set_cookie = res.headers.get("Set-Cookie", "")
            cookie_name = extract_session_cookie_name(set_cookie)
            if cookie_name:
                print(f"[CSRF] 세션 쿠키 이름 검출 성공: {path} → {cookie_name}")
                return cookie_name
        except Exception:
            continue

    return "accessToken"



def run_zap_scan(target_url: str, auth_tokens: list):
    """
    auth_tokens: [{"role": "user"|"seller"|"admin", "token": "<jwt>..."}, ...]
    빈 리스트이면 비인증 스캔으로 동작.
    """

    update_status(is_running=True, progress=0, message="ZAP 연결 및 포트 탐색 중...", result_file=None, total_alerts=0)
    
    # 1. 포트 자동 탐색 (8889, 8090)
    zap = None
    zap_port = 8889
    for port in [8889, 8090]:
        try:
            temp_zap = ZAPv2(proxies={'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'})
            # 간단한 API 호출로 연결 테스트
            temp_zap.core.version
            zap = temp_zap
            zap_port = port
            print(f"[+] ZAP Connected successfully on port {port}")
            break
        except Exception:
            continue
            
    if not zap:
        update_status(is_running=False, message="에러 발생: ZAP 프록시 서버(포트 8090 또는 8889)에 연결할 수 없습니다. ZAP이 켜져 있는지 확인해 주세요.")
        return

    try:
        # ── 다중 토큰 편의 변수 ───────────────────────────────────────────────
        # 권한 우선순위: admin > seller > user (ZAP 기본 인증에 사용할 대표 토큰)
        def account_role_rank(account: dict | None) -> int:
            role_text = str((account or {}).get("role", "")).lower()
            claims_text = str((account or {}).get("claims", {}) or {}).lower()
            joined = f"{role_text} {claims_text}"
            if "admin" in joined:
                return 0
            if "seller" in joined:
                return 1
            if "user" in joined:
                return 2
            return 3

        auth_tokens = sorted(auth_tokens or [], key=account_role_rank)
        primary_token = None
        primary_role = "anonymous"
        primary_account = None
        for priority_role in ["admin", "seller", "user"]:
            for t in auth_tokens:
                if priority_role in str(t.get("role", "")).lower() or priority_role in str(t.get("claims", {}) or {}).lower():
                    primary_token = t["token"]
                    primary_role = t.get("role", priority_role)
                    primary_account = t
                    break
            if primary_token:
                break
        if not primary_token and auth_tokens:
            primary_token = auth_tokens[0]["token"]
            primary_role = auth_tokens[0].get("role", "account")
            primary_account = auth_tokens[0]

        if auth_tokens:
            print(
                "[Auth] runner received accounts: "
                + ", ".join(f"{t.get('role', 'account')}@{t.get('base_url', target_url)}" for t in auth_tokens)
            )
            for t in auth_tokens:
                if t.get("token") and not t.get("claims"):
                    try:
                        _, token_claims = decode_jwt_claims(t.get("token"))
                        t["claims"] = token_claims
                    except Exception:
                        t["claims"] = {}
                print(f"[Auth] runner token claims for {t.get('role', 'account')}: {jwt_debug_summary(t.get('token'))}")
            print(f"[Auth] primary account for ZAP replacer: {primary_role}")

        # 엔드포인트별 최적 토큰 선택 캐시 (403 피하는 토큰 자동 탐색)
        try:
            zap.replacer.remove_rule(description="AutoLoginHeader")
            zap.replacer.remove_rule(description="AutoLoginCookie")
            print("[AuthMode] cleared stale ZAP auth replacer rules")
        except Exception:
            pass

        _token_cache = {}
        _path_param_cache = {}

        def extract_id_candidates_from_json(data, param_name: str, depth: int = 0) -> list:
            if depth > 5:
                return []

            candidates = []
            preferred_keys = [
                param_name,
                param_name.replace("Id", "ID"),
                param_name.replace("_id", "Id"),
                "id",
                "uuid",
                "key",
                "no",
                "seq",
            ]
            if isinstance(data, dict):
                for key in preferred_keys:
                    if key in data and data[key] is not None:
                        candidates.append(data[key])
                for value in data.values():
                    candidates.extend(extract_id_candidates_from_json(value, param_name, depth + 1))
            elif isinstance(data, list):
                for item in data[:10]:
                    candidates.extend(extract_id_candidates_from_json(item, param_name, depth + 1))

            deduped = []
            for value in candidates:
                value = str(value)
                if value and value not in deduped:
                    deduped.append(value)
            return deduped

        def resource_hint_for_param(param_name: str) -> str:
            return re.sub(r"(_?id|Id|ID)$", "", param_name).lower()

        def plural_resource_hints(hint: str) -> list:
            if not hint:
                return []
            hints = [hint]
            if hint.endswith("y"):
                hints.append(f"{hint[:-1]}ies")
            elif not hint.endswith("s"):
                hints.append(f"{hint}s")
            return list(dict.fromkeys(hints))

        def resolve_path_with_known_values(path: str, known_values: dict) -> str | None:
            resolved = path
            for param in re.findall(r"\{([^}]+)\}", resolved):
                if param not in known_values:
                    return None
                resolved = resolved.replace(f"{{{param}}}", str(known_values[param]))
            return resolved

        def discover_path_param_values(param_name: str, t_base: str, token: str, account: dict, known_values: dict, endpoints: dict) -> list:
            role = (account or {}).get("role", "account")
            cache_key = f"{role}:{t_base}:{param_name}:{json.dumps(known_values, sort_keys=True, default=str)}"
            if cache_key in _path_param_cache:
                return _path_param_cache[cache_key]

            hint = resource_hint_for_param(param_name)
            hint_variants = plural_resource_hints(hint)
            auth_headers = build_auth_headers(token, account)
            discovered = []

            probe_paths = []
            for hint_value in hint_variants:
                probe_paths.extend([f"/api/{hint_value}", f"/admin/{hint_value}"])

            for ep_path, ep_methods in (endpoints or {}).items():
                if "get" not in ep_methods:
                    continue
                if hint_variants and not any(h in ep_path.lower() for h in hint_variants):
                    continue
                probe_paths.append(ep_path)

            for ep_path in dict.fromkeys(probe_paths):

                resolved_ep_path = resolve_path_with_known_values(ep_path, known_values)
                if not resolved_ep_path:
                    continue

                try:
                    resp = requests.get(f"{t_base}{resolved_ep_path}", headers=auth_headers, timeout=3)
                    if not (200 <= resp.status_code < 400):
                        continue
                    discovered.extend(extract_id_candidates_from_json(resp.json(), param_name))
                except Exception:
                    continue

                if discovered:
                    break

            deduped = []
            for value in discovered:
                if value not in deduped:
                    deduped.append(value)
            _path_param_cache[cache_key] = deduped
            if deduped:
                print(f"[PathParam] {param_name} candidates for '{role}': {', '.join(deduped[:5])}")
            elif hint_variants:
                print(f"[PathParam] {param_name} no candidates for '{role}' via {', '.join(list(dict.fromkeys(probe_paths))[:5])}")
            return deduped

        def build_resolved_path_candidates(path_only: str, t_base: str, token: str, account: dict, endpoints: dict) -> list:
            params = re.findall(r"\{([^}]+)\}", path_only)
            if not params:
                return [path_only]

            candidates = [("", {})]
            for param in params:
                next_candidates = []
                for _, known_values in candidates:
                    values = discover_path_param_values(param, t_base, token, account, known_values, endpoints)
                    if "1" not in values:
                        values.append("1")
                    for value in values[:5]:
                        updated_values = dict(known_values)
                        updated_values[param] = value
                        resolved = path_only
                        for known_param, known_value in updated_values.items():
                            resolved = resolved.replace(f"{{{known_param}}}", str(known_value))
                        next_candidates.append((resolved, updated_values))
                candidates = next_candidates[:10]

            resolved_paths = []
            for resolved, _ in candidates:
                if "{" not in resolved and resolved not in resolved_paths:
                    resolved_paths.append(resolved)
            return resolved_paths or [re.sub(r"\{[^}]+\}", "1", path_only)]

        def select_token(api_url: str, method: str, preferred_account: dict | None = None) -> tuple:
            """각 엔드포인트에 대해 접근 가능한 (token, base_url, role) 튜플 반환.

            - preferred_account가 있으면 해당 계정만 평가하여 계정별 스캔을 강제함.
            - preferred_account가 없으면 입력된 auth_tokens 순서대로 시도함.
            - 계정별 base_url이 다른 경우, 해당 base_url로 재구성한 URL을 probe함.
            - 2xx/3xx 응답만 접근 성공으로 간주하고 4xx/5xx는 다음 계정을 계속 시도함.
            - 반환값: (token, effective_base_url, role_label)
            """
            preferred_role = (preferred_account or {}).get("role", "")
            cache_key = f"{preferred_role}_{method}_{api_url}"
            if cache_key in _token_cache:
                return _token_cache[cache_key]

            from urllib.parse import urlparse
            path_only = urlparse(api_url).path

            candidate_tokens = [preferred_account] if preferred_account else auth_tokens
            best_unverified_url = None
            for t in candidate_tokens:
                if not t:
                    continue
                token  = t["token"]
                role   = t.get("role", "account")
                t_base = t.get("base_url", target_url).rstrip("/")
                if not token:
                    result = (None, t_base, role, f"{t_base}{path_only}")
                    _token_cache[cache_key] = result
                    print(f"[TokenSelect] {method} {t_base}{path_only} → '{role}' (no auth)")
                    return result
                # 1. Path parameters translation using account-readable IDs when possible.
                resolved_path_candidates = build_resolved_path_candidates(path_only, t_base, token, t, t.get("validated_endpoints", {}))
                t_endpoints = t.get("validated_endpoints", {})
                t_swagger = t.get("swagger_components", {}) or swagger_components

                if resolved_path_candidates and best_unverified_url is None:
                    best_unverified_url = f"{t_base}{resolved_path_candidates[0]}"
                if method.upper() in {"POST", "PUT", "PATCH"}:
                    probe_url = best_unverified_url or f"{t_base}{path_only}"
                    result = (token, t_base, role, probe_url)
                    _token_cache[cache_key] = result
                    print(f"[TokenSelect] {method} {probe_url} -> '{role}' (mutation probe skipped)")
                    return result
                try:
                    probe_headers = build_auth_headers(token, t)

                    # 2. Build smart default body and query parameters from OpenAPI schemas if available for POST/PUT/PATCH
                    req_json = None
                    req_data = None
                    req_files = None
                    req_params = {}
                    if method.upper() in ["POST", "PUT", "PATCH"]:
                        # find path schema in endpoints metadata
                        matched_path_spec = None
                        # search for path_only (with curly braces) in t_endpoints
                        for ep_path, ep_methods in t_endpoints.items():
                            if ep_path.rstrip("/") == path_only.rstrip("/"):
                                matched_path_spec = ep_methods.get(method.lower())
                                break
                        if matched_path_spec:
                            # 2-1. Extract query parameters specified in parameters list
                            spec_params = matched_path_spec.get("parameters", [])
                            for p_spec in spec_params:
                                if isinstance(p_spec, dict) and p_spec.get("in") == "query":
                                    p_name = p_spec.get("name")
                                    p_schema = p_spec.get("schema", {})
                                    if p_name:
                                        req_params[p_name] = default_value_for_schema(p_schema, t_swagger, p_name)

                            # 2-2. Extract body
                            req_body_spec = matched_path_spec.get("requestBody", {})
                            if req_body_spec:
                                content = req_body_spec.get("content", {})
                                if "application/json" in content:
                                    req_json = {}
                                    json_schema = content.get("application/json", {}).get("schema", {})
                                    req_json = build_default_payload_from_schema(json_schema, t_swagger)
                                elif "multipart/form-data" in content:
                                    req_data = {}
                                    req_files = {}
                                    multipart_schema = resolve_schema_ref(
                                        content.get("multipart/form-data", {}).get("schema", {}),
                                        t_swagger,
                                    )
                                    for prop_name, prop_meta in multipart_schema.get("properties", {}).items():
                                        prop_type = get_schema_type(prop_meta, t_swagger)
                                        items_schema = resolve_schema_ref(prop_meta.get("items", {}), t_swagger)
                                        item_format = (items_schema.get("format") or "").lower() if isinstance(items_schema, dict) else ""
                                        if (
                                            (prop_type == "string" and (prop_meta.get("format") or "").lower() == "binary")
                                            or (prop_type == "array" and item_format == "binary")
                                        ):
                                            req_files[prop_name] = ("", b"", "application/octet-stream")
                                        else:
                                            req_data[prop_name] = default_value_for_schema(prop_meta, t_swagger, prop_name)

                    last_probe = None
                    last_probe_url = ""
                    for resolved_path in resolved_path_candidates:
                        probe_url = f"{t_base}{resolved_path}"
                        probe = requests.request(
                            method, probe_url,
                            headers=probe_headers,
                            params=req_params if req_params else None,
                            json=req_json,
                            data=req_data,
                            files=req_files,
                            timeout=3,
                        )
                        last_probe = probe
                        last_probe_url = probe_url
                        if 200 <= probe.status_code < 400:
                            result = (token, t_base, role, probe_url)
                            _token_cache[cache_key] = result
                            print(f"[TokenSelect] {method} {probe_url} → '{role}' ({probe.status_code})")
                            return result
                    if last_probe is not None:
                        print(
                            f"[TokenSelect] skip {method} {last_probe_url} → '{role}' "
                            f"({last_probe.status_code}) {summarize_response_for_log(last_probe)}"
                        )
                except Exception:
                    continue

            # 모든 토큰 실패 → 대표 토큰 반환
            if preferred_account:
                fallback_base = preferred_account.get("base_url", target_url).rstrip("/")
                fallback_url = best_unverified_url or f"{fallback_base}{re.sub(r'{[^}]+}', '1', path_only)}"
                return (
                    preferred_account.get("token"),
                    fallback_base,
                    preferred_account.get("role", "account"),
                    fallback_url,
                )
            fallback_base = target_url.rstrip("/")
            fallback_url = best_unverified_url or f"{fallback_base}{re.sub(r'{[^}]+}', '1', path_only)}"
            return (primary_token, fallback_base, primary_role, fallback_url)

        _identity_param_cache = {}

        def extract_identity_value(data, param_name: str):
            wanted = normalized_field_name(param_name)
            generic_keys = {"id", "userid", "memberid", "adminid", "accountid"}
            if isinstance(data, dict):
                for key, value in data.items():
                    normalized_key = normalized_field_name(key)
                    if value is not None and normalized_key == wanted:
                        return value
                for key, value in data.items():
                    normalized_key = normalized_field_name(key)
                    if value is not None and normalized_key in generic_keys:
                        return value
                for value in data.values():
                    found = extract_identity_value(value, param_name)
                    if found is not None:
                        return found
            elif isinstance(data, list):
                for item in data[:5]:
                    found = extract_identity_value(item, param_name)
                    if found is not None:
                        return found
            return None

        def resolve_identity_query_param(param_name: str, account: dict, token: str | None, base_url: str):
            normalized_param = normalized_field_name(param_name)
            if not (normalized_param == "id" or normalized_param.endswith("id")):
                return None
            cache_key = f"{account.get('role', 'account')}:{base_url}:{normalized_param}"
            if cache_key in _identity_param_cache:
                return _identity_param_cache[cache_key]

            claim_value = extract_identity_value(account.get("claims") or {}, param_name)
            if claim_value is not None:
                _identity_param_cache[cache_key] = claim_value
                return claim_value

            headers = build_auth_headers(token or account.get("token"), account)
            probe_paths = []
            for ep_path, ep_methods in (account.get("validated_endpoints") or {}).items():
                if "get" not in ep_methods or "{" in ep_path:
                    continue
                lowered = ep_path.lower()
                if "/me" in lowered or "profile" in lowered or "account" in lowered:
                    probe_paths.append(ep_path)

            for ep_path in list(dict.fromkeys(probe_paths))[:8]:
                try:
                    res = requests.get(f"{base_url.rstrip('/')}/{ep_path.lstrip('/')}", headers=headers, timeout=3)
                    if not (200 <= res.status_code < 400):
                        continue
                    value = extract_identity_value(res.json(), param_name)
                    if value is not None:
                        _identity_param_cache[cache_key] = value
                        print(f"[ParamResolve] {param_name}={value} from {ep_path} for {account.get('role', 'account')}")
                        return value
                except Exception:
                    continue

            _identity_param_cache[cache_key] = None
            return None

        # 2. 하이브리드 인증 세팅 (ZAP 프록시용 대표 토큰 주입)
        if False and primary_token:
            update_status(progress=3, message="인증 주입 설정 중 (Authorization Header & accessToken Cookie)...")
            try:
                zap.replacer.remove_rule(description="AutoLoginHeader")
                zap.replacer.remove_rule(description="AutoLoginCookie")
            except:
                pass

            bearer_token = primary_token if primary_token.startswith("Bearer ") else f"Bearer {primary_token}"
            zap.replacer.add_rule(
                description="AutoLoginHeader",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Authorization",
                replacement=bearer_token,
            )
        update_status(progress=5, message="입력된 API/URL 리스트 분석 및 취합 중...")
        
        # --- 계정별 개별 API 명세 수집 함수 정의 ---
        def build_endpoints_for_account(account: dict) -> tuple[dict, dict]:
            c_endpoints = {}
            s_components = {}
            op_url = account.get("openapi_url", "")
            u_list = account.get("url_list_str", "")
            a_list = account.get("api_list_str", "")
            b_url = account.get("base_url", target_url)
            
            # (A) Swagger OpenAPI 로드
            if op_url and op_url.strip():
                specs = [s.strip() for s in op_url.replace(',', '\n').split('\n') if s.strip()]
                for spec in specs:
                    sw_data = None
                    if spec.startswith("http"):
                        try:
                            zap.openapi.import_url(spec, b_url)
                            r = requests.get(spec, timeout=5)
                            if r.status_code == 200:
                                sw_data = r.json()
                        except:
                            pass
                    else:
                        local_path = os.path.abspath(spec)
                        if os.path.exists(local_path):
                            try:
                                zap.openapi.import_file(local_path, b_url)
                                with open(local_path, "r", encoding="utf-8") as f:
                                    sw_data = json.load(f)
                            except:
                                pass
                    
                    if sw_data and "paths" in sw_data:
                        for path, methods in sw_data["paths"].items():
                            c_endpoints.setdefault(path, {})
                            for method, details in methods.items():
                                if method.lower() in ["get", "post", "put", "delete", "options", "head", "patch"]:
                                    c_endpoints[path][method.lower()] = details
                        if "components" in sw_data and isinstance(sw_data["components"], dict):
                            for comp_type, comp_schemas in sw_data["components"].items():
                                s_components.setdefault(comp_type, {})
                                if isinstance(comp_schemas, dict):
                                    s_components[comp_type].update(comp_schemas)
            
            # (B) URL List
            if u_list and u_list.strip():
                for u in u_list.splitlines():
                    u = u.strip()
                    if not u: continue
                    path = u
                    if u.startswith(b_url):
                        path = u[len(b_url):]
                    path = path.split("?")[0]
                    c_endpoints.setdefault(path, {})
                    if "get" not in c_endpoints[path]:
                        c_endpoints[path]["get"] = {"parameters": [], "responses": {}}
                        
            # (C) API List
            if a_list and a_list.strip():
                for item in a_list.splitlines():
                    item = item.strip()
                    if not item: continue
                    parts = item.split(None, 1)
                    if len(parts) == 2:
                        method = parts[0].lower()
                        path = parts[1].strip()
                        if path.startswith(b_url):
                            path = path[len(b_url):]
                        path = path.split("?")[0]
                        c_endpoints.setdefault(path, {})
                        c_endpoints[path][method] = {"parameters": [], "responses": {}}
            return c_endpoints, s_components

        # 우선 스캔 시작 전 모든 계정의 개별 endpoints 수집
        for account in auth_tokens:
            existing_endpoints = account.get("validated_endpoints") if isinstance(account.get("validated_endpoints"), dict) else {}
            existing_components = account.get("swagger_components") if isinstance(account.get("swagger_components"), dict) else {}
            c_end, s_comp = build_endpoints_for_account(account)
            merged_endpoints = dict(existing_endpoints)
            for ep_path, methods in c_end.items():
                merged_endpoints.setdefault(ep_path, {}).update(methods or {})
            merged_components = dict(existing_components)
            for comp_type, comp_schemas in s_comp.items():
                if isinstance(comp_schemas, dict):
                    merged_components.setdefault(comp_type, {}).update(comp_schemas)
            account["validated_endpoints"] = merged_endpoints
            account["swagger_components"] = merged_components
            print(
                f"[Debug] Loaded {len(merged_endpoints)} endpoints for account '{account.get('role')}' "
                f"(preloaded={len(existing_endpoints)}, discovered={len(c_end)})"
            )
            
        # 미인증 스캔이 필요할 때를 위해 validated_endpoints 글로벌 폴백을 첫번째 계정이나 빈 값으로 초기화
        validated_endpoints = auth_tokens[0]["validated_endpoints"] if auth_tokens else {}
        swagger_components = auth_tokens[0]["swagger_components"] if auth_tokens else {}

        def auth_probe_paths(endpoints: dict, account: dict) -> list:
            paths = []
            excluded = ["login", "signup", "register", "refresh", "logout", "check-", "find-", "reset-password"]
            preferred = [
                "me",
                "profile",
                "account",
                "user",
                "member",
                "application",
                "notification",
                "dashboard",
                "setting",
                "order",
                "reservation",
            ]
            role = account.get("role", "account")
            role_lower = (role or "").lower()
            base_url = account.get("base_url", target_url)
            
            # role, token claims, or account base URL can identify an admin reader account.
            token_claims = account.get("claims", {}) or {}
            claims_str = str(token_claims).lower()
            base_url_text = str(base_url).lower()
            
            is_admin = (
                "admin" in role_lower
                or "admin" in claims_str
                or "admin" in base_url_text
            )
            
            if is_admin:
                preferred = [
                    "admin",
                    "dashboard",
                    "member",
                    "user",
                    "settlement",
                    "reservation",
                    "report",
                    "me",
                    "profile",
                ]

            for ep_path, ep_methods in endpoints.items():
                if "get" not in ep_methods:
                    continue
                lowered = ep_path.lower()
                if "{" in ep_path:
                    continue
                if any(marker in lowered for marker in excluded):
                    continue
                if is_admin and "admin" not in lowered:
                    continue
                if not is_admin and "admin" in lowered:  # 일반 유저가 어드민 경로를 검증하는 것 방어
                    continue
                if any(marker in lowered for marker in preferred):
                    paths.append(ep_path)

            for ep_path, ep_methods in endpoints.items():
                if len(paths) >= 12:
                    break
                lowered = ep_path.lower()
                if "get" not in ep_methods or "{" in ep_path:
                    continue
                if any(marker in lowered for marker in excluded):
                    continue
                if is_admin and "admin" not in lowered:
                    continue
                if not is_admin and "admin" in lowered:
                    continue
                if ep_path not in paths:
                    paths.append(ep_path)

            return list(dict.fromkeys(paths))[:12]

        def detect_account_auth_mode(account: dict) -> str:
            token = account.get("token")
            base_url = account.get("base_url", target_url).rstrip("/")
            role = account.get("role", "account")
            token_source = (account.get("token_source") or "").lower()
            token_field = account.get("token_field") or ""
            has_cookie = bool(build_cookie_header_from_account(account))
            candidates = auth_probe_paths(account.get("validated_endpoints", {}), account)
            if not candidates:
                if token_source == "cookie" or has_cookie:
                    return "cookie"
                if token_source in {"json", "header"}:
                    return "header"
                return "both"

            if token_source == "cookie":
                modes = [("cookie", "Cookie")]
                if token:
                    modes.extend([
                        ("header", "Authorization Bearer"),
                        ("authorization_raw", "Authorization raw"),
                        ("x_auth_token", "X-Auth-Token"),
                        ("access_token_header", "access-token"),
                        ("access_token_camel_header", "accessToken"),
                    ])
                modes.append(("both", "Authorization+Cookie"))
            elif token_source in {"json", "header"}:
                modes = [
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                ]
                if has_cookie:
                    modes.extend([("cookie", "Cookie"), ("both", "Authorization+Cookie")])
                else:
                    modes.append(("both", "Authorization+Cookie"))
            elif has_cookie:
                modes = [
                    ("cookie", "Cookie"),
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                    ("both", "Authorization+Cookie"),
                ]
            else:
                modes = [
                    ("header", "Authorization Bearer"),
                    ("authorization_raw", "Authorization raw"),
                    ("x_auth_token", "X-Auth-Token"),
                    ("access_token_header", "access-token"),
                    ("access_token_camel_header", "accessToken"),
                    ("both", "Authorization+Cookie"),
                ]

            seen_modes = set()
            modes = [(mode, label) for mode, label in modes if not (mode in seen_modes or seen_modes.add(mode))]
            print(
                f"[AuthMode] {role}: login response suggests "
                f"token_source={token_source or 'unknown'}"
                f"{f'({token_field})' if token_field else ''}, cookies={'yes' if has_cookie else 'no'}"
            )
            for mode, label in modes:
                headers = build_auth_headers(token, account, mode)
                if not headers:
                    continue
                for path in candidates:
                    try:
                        url = f"{base_url}{path}"
                        no_auth_resp = requests.get(url, timeout=3)
                        resp = requests.get(url, headers=headers, timeout=3)
                    except Exception:
                        continue
                    if 200 <= resp.status_code < 400 and no_auth_resp.status_code in [401, 403]:
                        print(
                            f"[AuthMode] {role}: verified {label} by protected GET {url} "
                            f"(no-auth {no_auth_resp.status_code} -> auth {resp.status_code})"
                        )
                        return mode
                    if 200 <= resp.status_code < 400 and 200 <= no_auth_resp.status_code < 400:
                        print(
                            f"[AuthMode] {role}: {label} not proven by public GET {url} "
                            f"(no-auth {no_auth_resp.status_code}, auth {resp.status_code})"
                        )
                    else:
                        print(
                            f"[AuthMode] {role}: {label} rejected by GET {url} "
                            f"(no-auth {no_auth_resp.status_code}, auth {resp.status_code})"
                        )

            print(f"[AuthMode] {role}: could not prove a single mode; disabling this account")
            account["auth_unverified"] = True
            return "disabled"

        had_auth_accounts = bool(auth_tokens)
        for account in auth_tokens:
            account["auth_mode"] = detect_account_auth_mode(account)
        auth_tokens = [account for account in auth_tokens if not account.get("auth_unverified")]
        if primary_account and primary_account.get("auth_unverified"):
            primary_account = auth_tokens[0] if auth_tokens else None
            primary_token = primary_account.get("token") if primary_account else None
            primary_role = primary_account.get("role", "anonymous") if primary_account else "anonymous"
        if had_auth_accounts and not auth_tokens:
            print("[AuthMode] no verified authenticated account remains; stopping scan to avoid unsafe fallback requests")
            update_status(is_running=False, message="인증 검증 실패: 보호 API에서 401이 반환되어 스캔을 중단했습니다.")
            return

        if primary_account:
            primary_token = primary_account.get("token")
            primary_role = primary_account.get("role", primary_role)

        def configure_zap_auth_replacer(account: dict | None):
            try:
                zap.replacer.remove_rule(description="AutoLoginHeader")
                zap.replacer.remove_rule(description="AutoLoginCookie")
            except Exception:
                pass

            if not account:
                return

            token = account.get("token")
            mode = (account.get("auth_mode") or "both").lower()
            role = account.get("role", "account")

            if mode in {"header", "both", "authorization_raw", "x_auth_token", "access_token_header", "access_token_camel_header"} and token:
                clean_token = str(token).replace("Bearer ", "").strip()
                header_name = "Authorization"
                header_value = f"Bearer {clean_token}"
                if mode == "authorization_raw":
                    header_value = clean_token
                elif mode == "x_auth_token":
                    header_name = "X-Auth-Token"
                    header_value = clean_token
                elif mode == "access_token_header":
                    header_name = "access-token"
                    header_value = clean_token
                elif mode == "access_token_camel_header":
                    header_name = "accessToken"
                    header_value = clean_token
                zap.replacer.add_rule(
                    description="AutoLoginHeader",
                    enabled=True,
                    matchtype="REQ_HEADER",
                    matchregex=False,
                    matchstring=header_name,
                    replacement=header_value,
                )

            if mode in {"cookie", "both"}:
                cookie_header = build_cookie_header_from_account(account)
                if not cookie_header and token:
                    session_cookie_name = detect_session_cookie(target_url, token, validated_endpoints)
                    cookie_header = f"{session_cookie_name}={str(token).replace('Bearer ', '').strip()}"
                if cookie_header:
                    zap.replacer.add_rule(
                        description="AutoLoginCookie",
                        enabled=True,
                        matchtype="REQ_HEADER",
                        matchregex=False,
                        matchstring="Cookie",
                        replacement=cookie_header,
                    )

            print(f"[AuthMode] ZAP replacer configured for {role}: {mode}")

        configure_zap_auth_replacer(primary_account)

        def format_http_request(req_obj):
            try:
                hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in req_obj.headers.items())
                body = req_obj.body
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                body_str = body if body else ""
                return f"{req_obj.method} {req_obj.url}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
            except Exception as e:
                return f"Request formatting error: {e}"

        def format_http_response(res_obj):
            try:
                hdrs = "\n".join(f'  "{k}": "{v}"' for k, v in res_obj.headers.items())
                body_str = res_obj.text if res_obj.text else ""
                # 프론트 표시를 위해 너무 긴 응답 바디는 1000자로 제어
                if len(body_str) > 1000:
                    body_str = body_str[:1000] + "\n... (응답 데이터가 너무 길어 중략됨)"
                return f"HTTP/1.1 {res_obj.status_code} {res_obj.reason}\n\nHeaders:\n{{\n{hdrs}\n}}\n\nBody:\n{body_str}"
            except Exception as e:
                return f"Response formatting error: {e}"

        def is_dangerous_endpoint(method: str, path: str, details: dict | None = None) -> tuple[bool, str]:
            method_upper = (method or "").upper()
            normalized_path = "/" + (path or "").lower().lstrip("/")
            details = details or {}

            # 1. DELETE 메소드는 데이터 파괴 및 세션 단절 위협이 극도로 높아 강제 스킵
            if method_upper == "DELETE":
                return True, "DELETE requests are skipped to protect active session and data integrity"

            # 2. Swagger details 정보 내 한글/영문 메타데이터 정적 분석
            summary = str(details.get("summary") or "").lower()
            description = str(details.get("description") or "").lower()
            
            critical_keywords = [
                "withdraw", "탈퇴", 
                "password-change", "change-password", "비밀번호 변경", "비밀번호변경",
                "logout", "로그아웃",
                "delete-account", "계정삭제", "계정 삭제"
            ]
            
            # 설명문이나 요약 정보에서 탈퇴, 비번변경, 로그아웃 등 위험 단어 매칭 시 차단
            if any(k in summary or k in description for k in critical_keywords):
                return True, f"API metadata (summary/description) matches safety block word"

            # 3. Request Body 내부의 스키마 분석 (오직 패스워드 변경 관련 전용 파라미터들로만 바인딩이 구성된 전용 변경 API만 차단)
            body_spec = details.get("requestBody", {}) or {}
            content = body_spec.get("content", {}) or {}
            json_schema = content.get("application/json", {}).get("schema", {}) or {}
            # schema reference 해결
            resolved_schema = resolve_schema_ref(json_schema, swagger_components)
            properties = resolved_schema.get("properties", {}) or {}
            
            password_indicators = ["newpassword", "currentpassword", "confirmpassword", "oldpassword", "password"]
            has_password_field = False
            has_normal_field = False
            for prop in properties.keys():
                if any(ind in prop.lower() for ind in password_indicators):
                    has_password_field = True
                else:
                    has_normal_field = True

            # 패스워드 필드가 포함되어 있으며, 프로필명/닉네임 등 일반 필드가 '전혀 없는' 순수 패스워드 변경용 API만 차단
            if has_password_field and not has_normal_field:
                return True, "Request body is restricted to sensitive credential modification only"

            # 4. 그 외 단순 상태 변경(승인/반려 등)이나 프로필 수정(/me/profile)은 스캔 진행 허용
            state_markers = [
                "/close",
                "/reopen",
                "/approve",
                "/reject",
                "/suspend",
                "/ban",
                "/unban",
            ]
            if method_upper == "PATCH" and any(marker in normalized_path for marker in state_markers):
                return True, "State-transition endpoint is protected from active scanning"

            return False, ""

        def extract_request_parts(req_obj, body_json=None, query_params=None):
            """Playwright / Selenium 자동화 재현을 위해 요청 구성 요소를 파싱된 딕셔너리로 반환합니다."""
            try:
                # 헤더 딕셔너리 (Playwright 재현 시 headers 옵션에 그대로 전달)
                parsed_headers = dict(req_obj.headers)

                # 바디: 이미 python dict 형태로 전달된 경우 그대로 사용, 아니면 raw body 파싱 시도
                parsed_body = None
                if body_json is not None:
                    parsed_body = body_json
                else:
                    raw_body = req_obj.body
                    if isinstance(raw_body, bytes):
                        raw_body = raw_body.decode("utf-8", errors="ignore")
                    if raw_body:
                        try:
                            parsed_body = json.loads(raw_body)
                        except Exception:
                            parsed_body = raw_body  # JSON 파싱 실패 시 raw 문자열 유지

                # 쿼리 파라미터
                parsed_query = query_params or {}

                # Content-Type 및 인증 정보 추출
                content_type = parsed_headers.get("Content-Type", parsed_headers.get("content-type", ""))
                auth_header = parsed_headers.get("Authorization", parsed_headers.get("authorization", ""))
                cookie_header = parsed_headers.get("Cookie", parsed_headers.get("cookie", ""))

                # Playwright fetch() 재현용 스크립트 스텁 생성
                body_snippet = json.dumps(parsed_body, ensure_ascii=False) if isinstance(parsed_body, dict) else repr(parsed_body)
                query_snippet = ("?" + "&".join(f"{k}={v}" for k, v in parsed_query.items())) if parsed_query else ""
                replay_script = (
                    f"// [Playwright] 재현 테스트 스크립트\n"
                    f"const response = await request.fetch('{req_obj.url}{query_snippet}', {{\n"
                    f"  method: '{req_obj.method}',\n"
                    f"  headers: {{\n"
                    f"    'Content-Type': '{content_type}',\n"
                    f"    'Authorization': '{auth_header}',\n"
                    f"    'Cookie': '{cookie_header}'\n"
                    f"  }},\n"
                    f"  data: {body_snippet}\n"
                    f"}});\n"
                    f"// 검증: 응답 본문 내 공격 페이로드 반사 확인\n"
                    f"const body = await response.text();\n"
                    f"expect(body).toContain('/* 공격 페이로드 삽입 */');"
                )

                return {
                    "parsed_request_headers": parsed_headers,
                    "parsed_request_body": parsed_body,
                    "parsed_request_query": parsed_query,
                    "auth_token_used": auth_header,
                    "login_required": bool(auth_header),
                    "replay_script": replay_script,
                }
            except Exception as e:
                return {
                    "parsed_request_headers": {},
                    "parsed_request_body": None,
                    "parsed_request_query": {},
                    "auth_token_used": "",
                    "login_required": False,
                    "replay_script": f"// extract_request_parts error: {e}",
                }

        session_cookie_name = detect_session_cookie(target_url, primary_token, validated_endpoints) if primary_token else "accessToken"
        custom_alerts = []
        cross_role_stored_seen = set()

        scan_accounts = auth_tokens if auth_tokens else [{"role": "anonymous", "token": None, "base_url": target_url}]
        def is_admin_account(account: dict) -> bool:
            role_text = str(account.get("role", "")).lower()
            base_url_text = str(account.get("base_url", "")).lower()
            claims_text = str(account.get("claims", {}) or {}).lower()
            return bool(account.get("token")) and (
                "admin" in role_text
                or "admin" in claims_text
                or "admin" in base_url_text
            )

        def account_role_text(account: dict | None) -> str:
            account = account or {}
            return " ".join(
                str(value or "").lower()
                for value in [
                    account.get("role"),
                    account.get("base_url"),
                    account.get("claims", {}),
                    account.get("email"),
                ]
            )

        def endpoint_role_priority(path_value: str, account: dict | None) -> tuple[int, str]:
            lowered = str(path_value or "").lower()
            role_text = account_role_text(account)
            is_admin = "admin" in role_text
            is_seller = "seller" in role_text
            if is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
                return (0, lowered)
            if is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
                return (0, lowered)
            if not is_admin and re.search(r"(^|/)admin(s)?(/|$)", lowered):
                return (3, lowered)
            if not is_seller and re.search(r"(^|/)seller(s)?(/|$)", lowered):
                return (3, lowered)
            return (1, lowered)

        admin_accounts = [account for account in auth_tokens if is_admin_account(account)]
        if admin_accounts:
            print(
                "[CROSS-ROLE STORED XSS] admin reader accounts: "
                + ", ".join(
                    f"{account.get('role', 'account')}@{account.get('base_url', target_url)}"
                    for account in admin_accounts
                )
            )
        else:
            print("[CROSS-ROLE STORED XSS] no admin reader account detected")

        def resource_tokens_from_path(path_value: str) -> set[str]:
            ignored = {
                "api", "v1", "v2", "admin", "admins", "seller", "sellers",
                "me", "auth", "login", "logout", "search", "check",
            }
            tokens = set()
            for segment in (path_value or "").split("/"):
                segment = segment.strip("{} ").lower()
                if not segment or segment in ignored or segment.startswith("{"):
                    continue
                if re.fullmatch(r"\d+", segment):
                    continue
                tokens.add(segment)
                if segment.endswith("ies") and len(segment) > 3:
                    tokens.add(segment[:-3] + "y")
                elif segment.endswith("s") and len(segment) > 1:
                    tokens.add(segment[:-1])
            if "profile" in tokens:
                tokens.update({"user", "users", "member", "members", "account", "accounts"})
            return tokens

        def cross_account_read_candidates_for_post(post_path: str, resource_id, writer_account: dict | None = None) -> list[tuple[dict, str, str, dict]]:
            post_tokens = resource_tokens_from_path(post_path)
            candidates = []
            writer_role = (writer_account or {}).get("role")
            writer_token = (writer_account or {}).get("token")
            reader_accounts = auth_tokens if auth_tokens else []
            for reader_account in reader_accounts:
                if writer_account and (
                    reader_account.get("token") == writer_token
                    or reader_account.get("role") == writer_role
                ):
                    continue
                reader_base = reader_account.get("base_url", target_url).rstrip("/")
                reader_endpoints = reader_account.get("validated_endpoints", validated_endpoints)
                for get_path, get_methods in reader_endpoints.items():
                    if "get" not in get_methods:
                        continue
                    lowered = get_path.lower()
                    get_tokens = resource_tokens_from_path(get_path)
                    if post_tokens and not (post_tokens & get_tokens):
                        continue
                    if "{" in get_path:
                        if not resource_id:
                            continue
                        resolved_path = re.sub(r"\{[^}]+\}", str(resource_id), get_path)
                    else:
                        resolved_path = get_path
                    reader_url = f"{reader_base}/{resolved_path.lstrip('/')}"
                    reader_params = build_query_defaults_from_details(get_methods.get("get") or {}, swagger_components)
                    for param_name in list(reader_params):
                        resolved_identity = resolve_identity_query_param(param_name, reader_account, reader_account.get("token"), reader_base)
                        if resolved_identity is not None:
                            reader_params[param_name] = resolved_identity
                    score = 0
                    if is_admin_account(reader_account) or "admin" in lowered:
                        score += 40
                    if resource_id and str(resource_id) in reader_url:
                        score += 20
                    if get_tokens & post_tokens:
                        score += 10
                    if get_path.rstrip("/") == post_path.rstrip("/"):
                        score += 12
                    elif get_path.rstrip("/").endswith(post_path.rstrip("/").split("/")[-1]):
                        score += 8
                    candidates.append((score, reader_account, get_path, reader_url, reader_params))

            deduped = []
            seen = set()
            for _, reader_account, get_path, reader_url, reader_params in sorted(candidates, key=lambda item: item[0], reverse=True):
                key = (reader_account.get("role"), reader_url, tuple(sorted(reader_params.items())))
                if key not in seen:
                    seen.add(key)
                    deduped.append((reader_account, get_path, reader_url, reader_params))
            return deduped[:20]

        def reflected_near_resource_id(response_text: str, payload: str, resource_id) -> bool:
            if not is_payload_reflected(payload, response_text):
                return False
            if not resource_id:
                return True
            rid = str(resource_id)
            if rid not in response_text:
                return False
            idx = response_text.find(rid)
            start_clip = max(0, idx - 250)
            end_clip = min(len(response_text), idx + 750)
            return payload in response_text[start_clip:end_clip]

        def verify_cross_account_stored_xss(post_path: str, post_url: str, resource_id, payload: str, param_name: str, writer_account: dict | None, writer_role: str):
            if not auth_tokens or len(auth_tokens) < 2:
                return
            for reader_account, reader_path, reader_url, reader_params in cross_account_read_candidates_for_post(post_path, resource_id, writer_account):
                reader_role = reader_account.get("role", "reader")
                seen_key = (post_url, reader_url, payload, str(resource_id), reader_role)
                if seen_key in cross_role_stored_seen:
                    continue
                cross_role_stored_seen.add(seen_key)
                try:
                    reader_headers = build_auth_headers(reader_account.get("token"), reader_account)
                    reader_res = requests.get(reader_url, headers=reader_headers, params=reader_params or None, timeout=4)
                except Exception as ce:
                    print(f"[CROSS-ACCOUNT STORED XSS DEBUG] reader GET fail on {reader_url} params={reader_params}: {ce}")
                    continue
                if not (200 <= reader_res.status_code < 400):
                    print(
                        f"[CROSS-ACCOUNT STORED XSS DEBUG] reader GET {reader_url} returned "
                        f"{reader_res.status_code}. Params: {reader_params}. Response: {summarize_response_for_log(reader_res)}"
                    )
                    continue
                url_has_resource = bool(resource_id and str(resource_id) in reader_url)
                if url_has_resource:
                    reflected = is_payload_reflected(payload, reader_res.text)
                else:
                    reflected = reflected_near_resource_id(reader_res.text, payload, resource_id)
                if not reflected:
                    continue

                reader_content_type = reader_res.headers.get("Content-Type", "").lower()
                print(
                    f"[CROSS-ACCOUNT STORED XSS] !!! CONFIRMED writer '{writer_role}' -> "
                    f"reader '{reader_role}' on {reader_url} (payload '{payload}' reflected) !!!"
                )
                response_params = infer_reflected_response_params(reader_res, payload)
                custom_alerts.append({
                    "alert": "Cross-Account Stored Cross-Site Scripting (Stored XSS) Vulnerability",
                    "url": reader_url,
                    "method": "GET",
                    "risk": "High",
                    "confidence": "High",
                    "param": param_name,
                    "reflected_response_params": response_params,
                    "attack": payload,
                    "status_code": reader_res.status_code,
                    "evidence": (
                        f"Payload stored by {writer_role} via mutation request {post_url} was reflected "
                        f"when read by {reader_role} via GET {reader_url}."
                    ),
                    "custom_type": "40014",
                    "evidence_request": format_http_request(reader_res.request),
                    "evidence_response": format_http_response(reader_res),
                    "expected_status_code": reader_res.status_code,
                    "expected_evidence_in_response": payload,
                    "cross_account_writer_role": writer_role,
                    "cross_account_reader_role": reader_role,
                    "cross_account_write_url": post_url,
                    "cross_account_read_url": reader_url,
                    "screenshot_on": "page_loaded",
                    "description": (
                        f"Input stored by one account boundary ({writer_role}) through {post_url} "
                        f"was later returned to another account boundary ({reader_role}) through "
                        f"{reader_url} without output encoding. "
                        f"(GET response Content-Type: {reader_content_type})"
                    )
                })


        print("[Auth] scan account order: " + ", ".join(f"{a.get('role', 'account')}@{a.get('base_url', target_url)}" for a in scan_accounts))

        for scan_account in scan_accounts:
            account_endpoints = scan_account.get("validated_endpoints", validated_endpoints)
            ordered_account_endpoints = sorted(
                account_endpoints.items(),
                key=lambda item: endpoint_role_priority(item[0], scan_account),
            )
            for path, methods in ordered_account_endpoints:
                for method, details in methods.items():
                    # 기본 api_url은 primary target 기준으로 구성 (select_token 내 path 추출용)
                    blocked, block_reason = is_dangerous_endpoint(method, path, details)
                    if blocked:
                        print(f"[Safety] skip {method.upper()} {path}: {block_reason}")
                        continue

                    api_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
    
                    # 이 엔드포인트에 대해 최적 토큰 + 실제 서비스 base_url + role 선택
                    best_token, best_base, best_role, selected_api_url = select_token(api_url, method.upper(), scan_account)
    
                    # 실제 스캔에 사용할 URL (계정별 base_url 기준)
                    api_url = selected_api_url
    
                    # 이 엔드포인트 스캔 시작 전 alert 개수 스냅샷 (끝에서 account_role 일괄 태깅용)
                    _alerts_snapshot = len(custom_alerts)
    
                    # (1) [SK 쉴더스 1-1] CSRF 공격 가능성 정밀 진단
                    # 중요 상태 변경을 일으키는 모든 POST/PUT/DELETE/PATCH API를 점검합니다.
                    if method.lower() in ["post", "put", "delete", "patch"]:
                        csrf_json_body = {}
                        csrf_body_spec = details.get("requestBody", {}) if isinstance(details, dict) else {}
                        csrf_content = csrf_body_spec.get("content", {}) if isinstance(csrf_body_spec, dict) else {}
                        if "application/json" in csrf_content:
                            csrf_schema = csrf_content.get("application/json", {}).get("schema", {})
                            csrf_json_body = build_default_payload_from_schema(
                                resolve_schema_ref(csrf_schema, swagger_components),
                                swagger_components,
                            )
                            
                        # 기본 인증 헤더에서 쿠키만 분리하여 준비
                        headers_cookie_only = {"Content-Type": "application/json"}
                        cookie_auth_header = build_cookie_header_from_account(scan_account)
                        if cookie_auth_header:
                            headers_cookie_only["Cookie"] = cookie_auth_header

                        # 공격 시나리오별 헤더 준비 (모두 Authorization 등 커스텀 토큰 제외, 쿠키만 포함)
                        # 1. Referer/Origin 변조 (해커 도메인)
                        headers_tampered_ref = {**headers_cookie_only, "Origin": "http://evil-attacker.local", "Referer": "http://evil-attacker.local/exploit.html"}
                        
                        # 2. Referer/Origin 누락 (삭제)
                        headers_no_ref = {**headers_cookie_only}
                        
                        try:
                            # 1. 자동 전송 수단(쿠키) 인증 통과 여부 테스트 (Authorization 헤더 전면 삭제)
                            res_cookie_only = requests.request(method=method.upper(), url=api_url, json=csrf_json_body, headers=headers_cookie_only, timeout=4)
                            status_cookie_only = res_cookie_only.status_code
                            
                            def is_passed(status):
                                return status < 400 or status == 405
                                
                            # 1차 검증: 백엔드가 쿠키만으로는 인증을 안 받아준다면 (예: 401/403)
                            # -> 헤더 토큰이 필수인 안전한 API이므로 CSRF 공격 불가능!
                            if not is_passed(status_cookie_only):
                                print(f"[CSRF DEBUG] {method.upper()} {api_url} -> CookieOnly: {status_cookie_only} (SAFE: Cookie auth rejected)")
                            else:
                                # --- 이 아래부터는 쿠키만으로 인증이 통과된(위험한) API에 대해서만 실행됨 ---
                                
                                # 2. Referer 변조 테스트 (변조된 Referer/Origin 포함)
                                res_tampered_ref = requests.request(method=method.upper(), url=api_url, json=csrf_json_body, headers=headers_tampered_ref, timeout=4)
                                status_tampered_ref = res_tampered_ref.status_code
                                
                                # 3. Referer 누락 테스트 (Origin, Referer 아예 없음)
                                res_no_ref = requests.request(method=method.upper(), url=api_url, json=csrf_json_body, headers=headers_no_ref, timeout=4)
                                status_no_ref = res_no_ref.status_code
                                
                                # 4. SameSite 속성 확인
                                set_cookie = res_tampered_ref.headers.get("Set-Cookie", "").lower()
                                has_unsafe_samesite = has_unsafe_samesite_cookie(scan_account, set_cookie)
                                if not cookie_auth_header:
                                    has_unsafe_samesite = True
                                    
                                # 판단 로직 (CSRF 토큰 누락은 이미 CookieOnly 테스트 통과로 뚫린 것으로 간주)
                                # High: 출처 검증 뚫림(tampered_ref) AND SameSite 속성 뚫림
                                is_high_risk = is_passed(status_tampered_ref) and has_unsafe_samesite
                                
                                # Medium: Referer 누락 시 에러 없이 통과됨
                                is_medium_risk = False
                                if not is_high_risk:
                                    if is_passed(status_no_ref):
                                        is_medium_risk = True

                                print(f"[CSRF DEBUG] {method.upper()} {api_url} -> CookieOnly: {status_cookie_only}, TamperedRef: {status_tampered_ref}, NoRef: {status_no_ref}, UnsafeSameSite: {has_unsafe_samesite}")
                                
                                if is_high_risk:
                                    csrf_req_parts = extract_request_parts(res_tampered_ref.request, body_json=csrf_json_body, query_params=None)
                                    custom_alerts.append({
                                        "alert": "Cross-Site Request Forgery (CSRF) Vulnerability - Confirmed",
                                        "url": api_url,
                                        "method": method.upper(),
                                        "risk": "High",
                                        "confidence": "High",
                                        "param": "Referer/Token/SameSite",
                                        "attack": "Tampered Referer & Missing Token & Unsafe SameSite",
                                        "custom_type": "CSRF_CUSTOM",
                                        "evidence_request": format_http_request(res_tampered_ref.request),
                                        "evidence_response": format_http_response(res_tampered_ref),
                                        "parsed_request_headers": csrf_req_parts["parsed_request_headers"],
                                        "parsed_request_body": csrf_req_parts["parsed_request_body"],
                                        "parsed_request_query": csrf_req_parts["parsed_request_query"],
                                        "auth_token_used": csrf_req_parts["auth_token_used"],
                                        "login_required": csrf_req_parts["login_required"],
                                        "expected_status_code": status_tampered_ref,
                                        "screenshot_on": "response_received",
                                        "replay_script": csrf_req_parts["replay_script"],
                                        "description": (
                                            "이 API는 3대 CSRF 방어선이 모두 뚫려있는 고위험(High) 상태입니다.\n"
                                            "1. 쿠키 의존성: Authorization 헤더 없이 브라우저의 자동 쿠키 전송만으로 API 인증을 허용함\n"
                                            "2. 출처 검증: 변조된 Referer(해커 도메인)를 전송해도 예외 없이 정상 처리함\n"
                                            "3. SameSite: 세션 쿠키에 SameSite 속성이 없거나 None으로 설정되어 브라우저가 자동 전송을 막지 못함\n"
                                            "결과적으로 타 사이트에서 위조된 요청이 성공하여 데이터가 변조될 위험이 매우 큽니다."
                                        ),
                                        "solution": "1. 헤더 기반(Bearer) 인증만 허용하도록 쿠키 Fallback 로직 제거\n2. 불가피할 경우 쿠키 발급 시 SameSite=Lax 적용\n3. Anti-CSRF 토큰 검증 로직 추가"
                                    })
                                elif is_medium_risk:
                                    csrf_req_parts = extract_request_parts(res_no_ref.request, body_json=csrf_json_body, query_params=None)
                                    custom_alerts.append({
                                        "alert": "Cross-Site Request Forgery (CSRF) Vulnerability - Potential/Bypass",
                                        "url": api_url,
                                        "method": method.upper(),
                                        "risk": "Medium",
                                        "confidence": "Medium",
                                        "param": "Referer/Token",
                                        "attack": "Omitted Referer or Token",
                                        "custom_type": "CSRF_CUSTOM",
                                        "evidence_request": format_http_request(res_no_ref.request),
                                        "evidence_response": format_http_response(res_no_ref),
                                        "parsed_request_headers": csrf_req_parts["parsed_request_headers"],
                                        "parsed_request_body": csrf_req_parts["parsed_request_body"],
                                        "parsed_request_query": csrf_req_parts["parsed_request_query"],
                                        "auth_token_used": csrf_req_parts["auth_token_used"],
                                        "login_required": csrf_req_parts["login_required"],
                                        "expected_status_code": status_no_ref,
                                        "screenshot_on": "response_received",
                                        "replay_script": csrf_req_parts["replay_script"],
                                        "description": (
                                            "이 API는 브라우저의 자동 전송 수단(쿠키)만으로 인증을 통과시켜 주는 결함이 있으며, 추가로 일부 출처(Referer) 우회 조건이 성립하여 잠재적 위험(Medium)이 존재합니다.\n"
                                            "해커 사이트 도메인(Tampered Referer)은 차단하고 있지만, 헤더를 아예 조작 삭제한 No Referer 상황에서는 방어 필터가 정상 작동하지 않고 200 OK 등을 반환합니다.\n\n"
                                            "**[수동 확인 필요 사항]**\n"
                                            "진단자는 Referer가 없을 때 서버 컨트롤러 내에서 403 예외 처리가 올바르게 되고 있는지 검증 로직을 수동으로 확인해야 합니다."
                                        ),
                                        "solution": "1. 헤더 기반(Bearer) 인증만 허용하도록 쿠키 Fallback 로직 제거\n2. 쿠키 발급 시 SameSite=Lax 또는 Strict 설정\n3. Referer 헤더 누락 시 엄격한 차단(403) 정책 적용"
                                    })

                        except Exception as ce:
                            print(f"CSRF Custom scan skip for {api_url}: {ce}")

                    # (2) [SK 쉴더스 1-1] XSS 공격 가능성 정밀 진단
                    # 다중 페이로드를 순회하여 WAF/필터 우회 변형 포함 탐지. 첫 검출 즉시 중단.
                    xss_headers = build_auth_headers(best_token, scan_account)
    
                    # Swagger에 정의된 파라미터 정보 추출 (루프 밖에서 1회만 수행)
                    parameters = details.get("parameters", [])
                    request_body_spec = details.get("requestBody", {})
    
                    base_test_params = {}
                    base_test_param_schemas = {}
                    base_param_defaults = {}
                    base_test_json_keys = []
                    base_test_json_schemas = {}
                    base_json_defaults = {}
                    base_json_required_defaults = {}
                    base_test_multipart_keys = []
                    base_test_multipart_schemas = {}
                    base_multipart_defaults = {}
                    base_multipart_required_defaults = {}
                    base_multipart_file_keys = []
    
                    for param_meta in parameters:
                        p_name = param_meta.get("name")
                        p_in = param_meta.get("in", "query")
                        p_schema = param_meta.get("schema")
                        if p_name and p_in == "query":
                            default_value = default_value_for_query_param(p_name, p_schema, swagger_components)
                            if default_value is not None:
                                base_param_defaults[p_name] = default_value
                            if is_xss_injectable_schema(p_schema, p_name, swagger_components):
                                base_test_params[p_name] = None  # XSS payload is injected only into string query params.
                                base_test_param_schemas[p_name] = resolve_schema_ref(p_schema or {}, swagger_components)
    
                    base_test_enum_defaults = {}
                    is_multipart_request = False
                    if request_body_spec:
                        content = request_body_spec.get("content", {})
                        if "multipart/form-data" in content:
                            is_multipart_request = True
                            multipart_schema = resolve_schema_ref(
                                content.get("multipart/form-data", {}).get("schema", {}),
                                swagger_components,
                            )
                            required_multipart_props = set(multipart_schema.get("required") or [])
                            for prop_name, prop_meta in multipart_schema.get("properties", {}).items():
                                default_multipart_value = default_value_for_schema(prop_meta, swagger_components, prop_name)
                                base_multipart_defaults[prop_name] = default_multipart_value
                                if prop_name in required_multipart_props:
                                    base_multipart_required_defaults[prop_name] = default_multipart_value
                                prop_type = get_schema_type(prop_meta, swagger_components)
                                items_schema = resolve_schema_ref(prop_meta.get("items", {}), swagger_components)
                                item_format = (items_schema.get("format") or "").lower() if isinstance(items_schema, dict) else ""
                                if looks_like_file_field(prop_name, prop_meta, swagger_components):
                                    base_multipart_file_keys.append(prop_name)
                                if is_xss_injectable_schema(prop_meta, prop_name, swagger_components):
                                    base_test_multipart_keys.append(prop_name)
                                    base_test_multipart_schemas[prop_name] = resolve_schema_ref(prop_meta, swagger_components)
                                if "enum" in prop_meta and prop_meta["enum"]:
                                    base_test_enum_defaults[prop_name] = prop_meta["enum"][0]
                        elif "application/json" in content:
                            json_schema = content.get("application/json", {}).get("schema", {})
                            resolved_json_schema = resolve_schema_ref(json_schema, swagger_components)
                            base_test_json_keys = extract_injectable_keypaths(resolved_json_schema, components=swagger_components)
                            base_test_json_schemas = {
                                keypath: schema_for_keypath(resolved_json_schema, keypath, swagger_components)
                                for keypath in base_test_json_keys
                            }
                            base_json_defaults = build_default_payload_from_schema(resolved_json_schema, swagger_components)
                            base_json_required_defaults = build_required_payload_from_schema(resolved_json_schema, swagger_components)
                            for prop_name, prop_meta in resolved_json_schema.get("properties", {}).items():
                                if "enum" in prop_meta and prop_meta["enum"]:
                                    base_test_enum_defaults[prop_name] = prop_meta["enum"][0]

                    for param_name in list(base_param_defaults):
                        resolved_identity = resolve_identity_query_param(param_name, scan_account, best_token, best_base)
                        if resolved_identity is not None:
                            base_param_defaults[param_name] = resolved_identity

                    def multipart_files_for_request():
                        if not base_multipart_file_keys:
                            return None
                        # Match real multipart upload flows: if the OpenAPI request declares file
                        # fields, include a harmless 1x1 PNG even when the field is optional.
                        png_1x1 = base64.b64decode(
                            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/ax"
                            "p3n8AAAAASUVORK5CYII="
                        )
                        return {
                            key: ("argus-test.png", png_1x1, "image/png")
                            for key in base_multipart_file_keys
                        }
    
                    # Path parameters have already been resolved by select_token using readable IDs.
                    resolved_api_url = api_url

                    # 고도화 6: Baseline 사전 요청 전송 (Diff 기반 오탐 방지 목적)
                    baseline_params = dict(base_param_defaults)
                    baseline_json = copy.deepcopy(base_json_required_defaults)
                    for k in base_test_json_keys:
                        top_key = k.split(".", 1)[0].replace("[0]", "")
                        if top_key not in base_json_required_defaults:
                            continue
                        prop_name = k.split(".")[-1]
                        dummy_val = default_value_for_schema(base_test_json_schemas.get(k, {"type": "string"}), swagger_components, prop_name)
                        set_nested_value_by_keypath(baseline_json, k, dummy_val)
                    baseline_multipart = dict(base_multipart_required_defaults)
                    for k in base_test_multipart_keys:
                        if k not in base_multipart_required_defaults:
                            continue
                        dummy_val = default_value_for_schema({"type": "string"}, swagger_components, k)
                        baseline_multipart[k] = base_test_enum_defaults.get(k, dummy_val)
    
                    baseline_body = None
                    baseline_status = None
                    try:
                        req_headers = {**xss_headers}
                        if not is_multipart_request and base_test_json_keys:
                            req_headers["Content-Type"] = "application/json"
                        elif is_multipart_request:
                            # requests가 자동으로 boundary를 가진 Content-Type 헤더를 채우도록 대소문자 구분 없이 소거
                            for ct_key in [k for k in req_headers.keys() if k.lower() == "content-type"]:
                                req_headers.pop(ct_key, None)
    
                        res_base = requests.request(
                            method=method.upper(),
                            url=resolved_api_url,
                            params=baseline_params if baseline_params else None,
                            json=baseline_json if (baseline_json and not is_multipart_request) else None,
                            data=baseline_multipart if (is_multipart_request and baseline_multipart) else None,
                            files=multipart_files_for_request() if is_multipart_request else None,
                            headers=req_headers,
                            timeout=4
                        )
                        baseline_status = res_base.status_code
                        baseline_body = res_base.text
                        print(
                            f"[HTTP TRACE] baseline {method.upper()} {resolved_api_url} "
                            f"role={best_role} status={res_base.status_code} "
                            f"params={baseline_params or {}} "
                            f"json_keys={list(baseline_json.keys()) if isinstance(baseline_json, dict) and baseline_json else []} "
                            f"multipart_keys={list(baseline_multipart.keys()) if baseline_multipart else []} "
                            f"file_keys={base_multipart_file_keys if is_multipart_request else []} "
                            f"content_type={res_base.headers.get('Content-Type', '')} "
                            f"response={summarize_response_for_log(res_base, 300)}"
                        )
                    except Exception as be:
                        print(f"[XSS Baseline DEBUG] Failed to get baseline response: {be}")

                    if baseline_status in [401, 403]:
                        print(f"[XSS DEBUG] skip fuzzing -> {method.upper()} {resolved_api_url} baseline returned {baseline_status} for account '{best_role}'")
                        continue
    
#                     reflected_xss_detected = False
#                     successful_payloads = []
#                     xss_first_result = None
#                     xss_first_req_parts = None
#                     xss_first_res = None
#                     xss_first_content_type = ""
#                     xss_first_x_content_type = ""
#                     target_vulnerable_param = ""
#     
#                     # 테스트 대상 파라미터 후보 리스트 (쿼리 파라미터 + JSON 바디 키 + Multipart 폼 필드)
#                     params_to_test = []
#                     for q_param in base_test_params.keys():
#                         params_to_test.append(("query", q_param, base_test_param_schemas.get(q_param, {"type": "string"})))
#                     for j_key in base_test_json_keys:
#                         params_to_test.append(("json", j_key, base_test_json_schemas.get(j_key, {"type": "string"})))
#                     for m_key in base_test_multipart_keys:
#                         params_to_test.append(("multipart", m_key, base_test_multipart_schemas.get(m_key, {"type": "string"})))
#     
#                     for target_type, target_param, target_schema in params_to_test:
#                         field_payloads = payloads_for_xss_field(target_param, target_schema, swagger_components)
#                         if not field_payloads:
#                             print(f"[XSS DEBUG] skip field -> {method.upper()} {resolved_api_url} | param: {target_param} ({target_type}) not suitable for XSS payloads")
#                             continue
#                         for xss_payload in field_payloads:
#                             # 타겟 파라미터 하나만 페이로드를 주입하고, 나머지는 안전한 기본값("safe")을 설정함
#                             test_params = dict(base_param_defaults)
#                             if target_type == "query":
#                                 test_params[target_param] = xss_payload
#                             
#                             # JSON Fuzzing 딕셔너리 구성: non-string fields keep type-correct defaults.
#                             test_json = copy.deepcopy(base_json_required_defaults)
#                             for k in base_test_json_keys:
#                                 top_key = k.split(".", 1)[0].replace("[0]", "")
#                                 if target_type != "json" and top_key not in base_json_required_defaults:
#                                     continue
#                                 prop_name = k.split(".")[-1]
#                                 dummy_val = default_value_for_schema(base_test_json_schemas.get(k, {"type": "string"}), swagger_components, prop_name)
#                                 set_nested_value_by_keypath(test_json, k, dummy_val)
#                             if target_type == "json":
#                                 set_nested_value_by_keypath(test_json, target_param, xss_payload)
#                             
#                             # Multipart Fuzzing 딕셔너리 구성: payload only goes into string fields.
#                             test_multipart = dict(base_multipart_required_defaults)
#                             for k in base_test_multipart_keys:
#                                 if target_type != "multipart" and k not in base_multipart_required_defaults:
#                                     continue
#                                 dummy_val = default_value_for_schema({"type": "string"}, swagger_components, k)
#                                 test_multipart[k] = base_test_enum_defaults.get(k, dummy_val)
#                             if target_type == "multipart":
#                                 test_multipart[target_param] = xss_payload
#     
#                             try:
#                                 req_headers = {**xss_headers}
#                                 if target_type == "json":
#                                     req_headers["Content-Type"] = "application/json"
#                                 elif is_multipart_request:
#                                     # requests가 자동으로 boundary를 가진 Content-Type 헤더를 채우도록 대소문자 구분 없이 소거
#                                     for ct_key in [k for k in req_headers.keys() if k.lower() == "content-type"]:
#                                         req_headers.pop(ct_key, None)
#     
#                                 print(f"[XSS DEBUG] testing -> {method.upper()} {resolved_api_url} | param: {target_param} ({target_type}) | payload: {xss_payload[:30]}...")
#                                 res_xss = requests.request(
#                                     method=method.upper(),
#                                     url=resolved_api_url,
#                                     params=test_params if test_params else None,
#                                     json=test_json if (test_json and target_type == "json") else None,
#                                     data=test_multipart if (is_multipart_request and test_multipart) else None,
#                                     files=multipart_files_for_request() if is_multipart_request else None,
#                                     headers=req_headers,
#                                     timeout=4
#                                 )
#     
#                                 res_body = res_xss.text
#                                 x_content_type = res_xss.headers.get("X-Content-Type-Options", "").lower()
#                                 content_type = res_xss.headers.get("Content-Type", "").lower()
#                                 print(
#                                     f"[HTTP TRACE] xss {method.upper()} {resolved_api_url} "
#                                     f"role={best_role} param={target_param} target_type={target_type} "
#                                     f"status={res_xss.status_code} params={test_params or {}} "
#                                     f"json_keys={list(test_json.keys()) if isinstance(test_json, dict) and test_json else []} "
#                                     f"multipart_keys={list(test_multipart.keys()) if test_multipart else []} "
#                                     f"file_keys={base_multipart_file_keys if is_multipart_request else []} "
#                                     f"content_type={res_xss.headers.get('Content-Type', '')} "
#                                     f"payload_reflected={is_payload_reflected(xss_payload, res_body, baseline_body)} "
#                                     f"response={summarize_response_for_log(res_xss, 300)}"
#                                 )
#     
#                                 # 4xx/5xx 에러 응답은 XSS로 처리하지 않음 (에러 페이지 반사는 6-1 영역)
#                                 if res_xss.status_code >= 400:
#                                     print(f"[XSS DEBUG] skipped -> {method.upper()} {api_url} returned status {res_xss.status_code}. Response: {res_body[:200]}")
#                                     if looks_like_validation_rejection(res_xss):
#                                         print(f"[XSS DEBUG] stop field -> {method.upper()} {resolved_api_url} | param: {target_param} rejected by validation")
#                                         break
#                                     continue
#     
#     
#                                 # 고도화 6: baseline_body를 공급하여 Diff 영역에서만 반사 여부 검증
#                                 xss_result = classify_xss_response(
#                                     payload=xss_payload,
#                                     response_body=res_body,
#                                     content_type=content_type,
#                                     method=method.upper(),
#                                     is_mutation=(target_type in ["json", "multipart"]),
#                                     response_headers=res_xss.headers,
#                                     baseline_body=baseline_body
#                                 )
#     
#     
#                                 if xss_result:
#                                     reflected_xss_detected = True
#                                     target_vulnerable_param = target_param
#                                     if xss_payload not in successful_payloads:
#                                         successful_payloads.append(xss_payload)
#                                     
#                                     # 첫 번째 감지 시, 반사 컨텍스트에 맞춰 2차 정밀 스캔 진행 (2차 우회 최적화)
#                                     if not xss_first_result:
#                                         xss_first_result = xss_result
#                                         xss_first_res = res_xss
#                                         xss_first_content_type = content_type
#                                         xss_first_x_content_type = x_content_type
#                                         
#                                         # ── XSS 고도화 2단계: 컨텍스트 기반 2차 정밀 페이로드 검증 ──
#                                         reflection_ctx = xss_result.get("reflection_context", "HTML body")
#                                         context_specific_payloads = CONTEXT_PAYLOADS.get(reflection_ctx, [])
#                                         
#                                         for ctx_payload in context_specific_payloads:
#                                             t_params_2 = dict(base_param_defaults)
#                                             if target_type == "query":
#                                                 t_params_2[target_param] = ctx_payload
#                                             t_json_2 = copy.deepcopy(base_json_required_defaults)
#                                             for k in base_test_json_keys:
#                                                 top_key = k.split(".", 1)[0].replace("[0]", "")
#                                                 if target_type != "json" and top_key not in base_json_required_defaults:
#                                                     continue
#                                                 set_nested_value_by_keypath(t_json_2, k, "safe")
#                                             if target_type == "json":
#                                                 set_nested_value_by_keypath(t_json_2, target_param, ctx_payload)
#                                             t_multipart_2 = dict(base_multipart_required_defaults)
#                                             if target_type == "multipart":
#                                                 t_multipart_2[target_param] = ctx_payload
#                                             try:
#                                                 req_headers_2 = {**xss_headers}
#                                                 if target_type == "json":
#                                                     req_headers_2["Content-Type"] = "application/json"
#                                                 elif is_multipart_request:
#                                                     req_headers_2.pop("Content-Type", None)
#                                                 res_ctx_2 = requests.request(
#                                                     method=method.upper(),
#                                                     url=api_url,
#                                                     params=t_params_2 if t_params_2 else None,
#                                                     json=t_json_2 if (t_json_2 and target_type == "json") else None,
#                                                     data=t_multipart_2 if (is_multipart_request and t_multipart_2) else None,
#                                                     files=multipart_files_for_request() if is_multipart_request else None,
#                                                     headers=req_headers_2,
#                                                     timeout=4
#                                                 )
#                                                 result_2 = classify_xss_response(
#                                                     payload=ctx_payload,
#                                                     response_body=res_ctx_2.text,
#                                                     content_type=content_type,
#                                                     method=method.upper(),
#                                                     is_mutation=(target_type == "json"),
#                                                     response_headers=res_ctx_2.headers,
#                                                     baseline_body=baseline_body
#                                                 )
#                                                 if result_2:
#                                                     if ctx_payload not in successful_payloads:
#                                                         successful_payloads.append(ctx_payload)
#                                                     # 컨텍스트에 맞춘 증거 패킷으로 대표값 업데이트
#                                                     xss_first_result = result_2
#                                                     xss_first_res = res_ctx_2
#                                                     xss_payload = ctx_payload
#                                             except Exception:
#                                                 continue
#     
#                                         # 스크립트 작성용 파싱 추출
#                                         xss_first_req_parts = extract_request_parts(
#                                             xss_first_res.request,
#                                             body_json=test_json if target_type == "json" else None,
#                                             query_params=test_params if target_type == "query" else None
#                                         )
#     
#                             except Exception as xe:
#                                 print(f"XSS Custom scan skip for {api_url} ({target_param}): {xe}")
#     
#                     if reflected_xss_detected and xss_first_result:
#                         print(f"[XSS DEBUG] !!! {xss_first_result['kind'].upper()} XSS DETECTED on {api_url} (Param: {target_vulnerable_param}, Success Payloads: {len(successful_payloads)}) !!!")
#     
#                         replay_with_payload = xss_first_req_parts["replay_script"].replace(
#                             "'/* 공격 페이로드 삽입 */'",
#                             repr(successful_payloads[0])
#                         )
#                         custom_alerts.append({
#                             "alert": xss_first_result["alert"],
#                             "url": api_url,
#                             "method": method.upper(),
#                             "risk": xss_first_result["risk"],
#                             "confidence": xss_first_result["confidence"],
#                             "param": target_vulnerable_param,
#                             "attack": successful_payloads[0],
#                             "status_code": xss_first_res.status_code,
#                             "evidence": xss_first_result["evidence"],
#                             "custom_type": xss_first_result["custom_type"],
#                             "evidence_request": format_http_request(xss_first_res.request),
#                             "evidence_response": format_http_response(xss_first_res),
#                             "parsed_request_headers": xss_first_req_parts["parsed_request_headers"],
#                             "parsed_request_body": xss_first_req_parts["parsed_request_body"],
#                             "parsed_request_query": xss_first_req_parts["parsed_request_query"],
#                             "auth_token_used": xss_first_req_parts["auth_token_used"],
#                             "login_required": xss_first_req_parts["login_required"],
#                             "expected_status_code": xss_first_res.status_code,
#                             "expected_evidence_in_response": successful_payloads[0],
#                             "screenshot_on": "response_received",
#                             "replay_script": replay_with_payload,
#                             "successful_attack_payloads": successful_payloads,
#                             "description": (
#                                 f"{xss_first_result['description']} "
#                                 f"(응답 마임타입: {xss_first_content_type}, 보안헤더 nosniff 누락 상태: {'Y' if 'nosniff' not in xss_first_x_content_type else 'N'})"
#                             )
#                         })
#     
                    # ── XSS 고도화 3단계: HTTP 헤더 인젝션 XSS (Header Injection) ──
                    # User-Agent, Referer, X-Forwarded-For 등 클라이언트 전송 헤더가 응답 페이지나 에러 출력에 그대로 반사되는 취약점을 진단합니다.
                    INJECTABLE_HEADERS = [
                        "User-Agent",
                        "Referer",
                        "X-Forwarded-For",
                        "X-Real-IP",
                        "X-Custom-Header",
                    ]
    
                    for header_name in INJECTABLE_HEADERS:
                        header_payload = "<script>alert('header')</script>"
                        inject_headers = {**xss_headers, header_name: header_payload}
                        
                        # Origin이나 Referer의 경우 타 도메인 검증에 영향이 없도록 Referer 헤더 인젝션 시에만 덮어씀
                        if header_name == "Referer":
                            inject_headers["Referer"] = header_payload
                            
                        try:
                            res_hdr = requests.request(
                                method=method.upper(),
                                url=api_url,
                                headers=inject_headers,
                                timeout=4
                            )
                            x_content_type = res_hdr.headers.get("X-Content-Type-Options", "").lower()
                            content_type = res_hdr.headers.get("Content-Type", "").lower()
    
                            # 4xx/5xx 에러 응답은 XSS로 처리하지 않음
                            if res_hdr.status_code >= 400:
                                continue
    
                            hdr_xss_result = classify_xss_response(
                                payload=header_payload,
                                response_body=res_hdr.text,
                                content_type=content_type,
                                method=method.upper(),
                                is_mutation=False,
                                response_headers=res_hdr.headers,
                            )
                            
                            if hdr_xss_result:
                                print(f"[XSS DEBUG] !!! HEADER XSS DETECTED on {api_url} via {header_name} !!!")
                                hdr_req_parts = extract_request_parts(res_hdr.request)
                                custom_alerts.append({
                                    "alert": f"Header-based Cross-Site Scripting (XSS) via {header_name}",
                                    "url": api_url,
                                    "method": method.upper(),
                                    "risk": "Medium",
                                    "confidence": "High",
                                    "param": header_name,
                                    "attack": header_payload,
                                    "status_code": res_hdr.status_code,
                                    "evidence": f"HTTP 요청 헤더 '{header_name}'에 주입된 페이로드가 응답 본문에 그대로 실행 가능한 형태로 반사됨",
                                    "custom_type": "40012",
                                    "evidence_request": format_http_request(res_hdr.request),
                                    "evidence_response": format_http_response(res_hdr),
                                    "parsed_request_headers": hdr_req_parts["parsed_request_headers"],
                                    "parsed_request_body": hdr_req_parts["parsed_request_body"],
                                    "parsed_request_query": hdr_req_parts["parsed_request_query"],
                                    "auth_token_used": hdr_req_parts["auth_token_used"],
                                    "login_required": hdr_req_parts["login_required"],
                                    "expected_status_code": res_hdr.status_code,
                                    "expected_evidence_in_response": header_payload,
                                    "screenshot_on": "response_received",
                                    "replay_script": hdr_req_parts["replay_script"],
                                    "description": f"요청 헤더 '{header_name}' 값을 통해 입력한 악성 스크립트가 적절한 필터링 없이 화면에 출력되어 XSS 공격에 악용될 수 있습니다.",
                                    "solution": f"로그 화면 또는 에러 메시지 출력 페이지에서 '{header_name}' 헤더 값을 렌더링할 때 특수 문자(<, >, &, \")를 인코딩 처리(HTML Entity Escape) 하십시오."
                                })
                                break # 하나의 헤더에서 발생이 증명되면 중단
                        except Exception:
                            continue
    
    
    
                    # ── Stored XSS 2단계 검증 (POST→GET 재조회) ───────────────────────────────
                    # POST 엔드포인트에서 4종의 페이로드 저장 시도 후, 모든 GET 엔드포인트에 대해 자원 ID를 대입하여 브로드캐스트 조회
                    if method.lower() in {"post", "put", "patch"}:
                        # 고도화 2: 1종이 아닌 상위 4종의 주요 XSS 변형군으로 저장 시도
                        stored_targets = []
                        for q_param in base_test_params.keys():
                            stored_targets.append(("query", q_param, base_test_param_schemas.get(q_param, {"type": "string"})))
                        for j_key in base_test_json_keys:
                            stored_targets.append(("json", j_key, base_test_json_schemas.get(j_key, {"type": "string"})))
                        for m_key in base_test_multipart_keys:
                            stored_targets.append(("multipart", m_key, base_test_multipart_schemas.get(m_key, {"type": "string"})))
                        stored_trials = []
                        for target_type, target_param, target_schema in stored_targets:
                            for base_stored_payload in payloads_for_xss_field(target_param, target_schema, swagger_components)[:4]:
                                stored_payload = make_unique_xss_payload(base_stored_payload, target_param)
                                stored_trials.append((target_type, target_param, stored_payload))
                        # Stored XSS는 원인 필드 추적을 위해 한 번에 하나의 파라미터에만 payload를 저장한다.
                        for target_type, target_param, stored_payload in stored_trials:
                            store_params = dict(base_param_defaults)
                            if target_type == "query":
                                store_params[target_param] = stored_payload

                            store_json = copy.deepcopy(base_json_required_defaults)
                            for k in base_test_json_keys:
                                top_key = k.split(".", 1)[0].replace("[0]", "")
                                if target_type != "json" and top_key not in base_json_required_defaults:
                                    continue
                                prop_name = k.split(".")[-1]
                                dummy_val = default_value_for_schema(base_test_json_schemas.get(k, {"type": "string"}), swagger_components, prop_name)
                                set_nested_value_by_keypath(store_json, k, base_test_enum_defaults.get(prop_name, dummy_val))
                            if target_type == "json":
                                set_nested_value_by_keypath(store_json, target_param, stored_payload)
                            
                            store_multipart = dict(base_multipart_required_defaults)
                            for k in base_test_multipart_keys:
                                if target_type != "multipart" and k not in base_multipart_required_defaults:
                                    continue
                                dummy_val = default_value_for_schema({"type": "string"}, swagger_components, k)
                                store_multipart[k] = base_test_enum_defaults.get(k, dummy_val)
                            if target_type == "multipart":
                                store_multipart[target_param] = stored_payload
                                
                            try:
                                post_headers = {**xss_headers}
                                if not is_multipart_request and base_test_json_keys:
                                    post_headers["Content-Type"] = "application/json"
                                elif is_multipart_request:
                                    post_headers.pop("Content-Type", None)

                                # [Stored XSS 오탐 방지] POST 저장 전에 미리 모든 GET 엔드포인트의 Baseline 상태를 백업
                                get_baselines = {}
                                for get_path, get_methods in account_endpoints.items():
                                    if "get" not in get_methods:
                                        continue
                                    # 임시 1번 ID로 치환하여 Baseline 백업 시도
                                    import re as _re
                                    tmp_path = _re.sub(r"\{[^}]+\}", "1", get_path)
                                    tmp_url = f"{best_base.rstrip('/')}/{tmp_path.lstrip('/')}"
                                    tmp_params = build_query_defaults_from_details(get_methods.get("get") or {}, swagger_components)
                                    try:
                                        tmp_res = requests.get(tmp_url, headers=xss_headers, params=tmp_params or None, timeout=3)
                                        if tmp_res.status_code == 200:
                                            get_baselines[get_path] = tmp_res.text
                                    except Exception:
                                        pass

                                post_res = requests.request(
                                    method.upper(),
                                    api_url,
                                    params=store_params if store_params else None,
                                    json=store_json if (store_json and not is_multipart_request) else None,
                                    data=store_multipart if (is_multipart_request and store_multipart) else None,
                                    files=multipart_files_for_request() if is_multipart_request else None,
                                    headers=post_headers,
                                    timeout=4
                                )
                                if post_res.status_code in [200, 201]:
                                    # 생성된 리소스 ID 추출
                                    resource_id = None
                                    try:
                                        resp_json = post_res.json()
                                        resource_id = extract_id_from_response(resp_json)
                                    except Exception:
                                        pass
                                    if not resource_id:
                                        resource_id = extract_id_from_url(api_url)
                                    verify_cross_account_stored_xss(
                                        post_path=path,
                                        post_url=api_url,
                                        resource_id=resource_id,
                                        payload=stored_payload,
                                        param_name=target_param,
                                        writer_account=scan_account,
                                        writer_role=best_role,
                                    )
    
                                    # 모든 GET 엔드포인트를 순회하며 치환 및 조회
                                    for get_path, get_methods in account_endpoints.items():
                                        if "get" not in get_methods:
                                            continue
                                        
                                        # 경로 변수가 존재하는 경우 resource_id로 대입 치환
                                        if resource_id and "{" in get_path:
                                            resolved_path = _re.sub(r"\{[^}]+\}", str(resource_id), get_path)
                                        else:
                                            resolved_path = get_path

                                        get_url = f"{best_base.rstrip('/')}/{resolved_path.lstrip('/')}"
                                        get_params = build_query_defaults_from_details(get_methods.get("get") or {}, swagger_components)
                                        try:
                                            get_res = requests.get(get_url, headers=xss_headers, params=get_params or None, timeout=4)
                                            # 해당 GET 엔드포인트 전용으로 백업해둔 Baseline 본문 가져오기
                                            specific_baseline = get_baselines.get(get_path)
                                            
                                            # 전용 Baseline 대비 신규 반사 여부 검증
                                            if is_payload_reflected(stored_payload, get_res.text, specific_baseline):
                                                # [Strict Stored XSS Verification]
                                                # 1) 개별 조회 주소(GET /api/v1/posts/4)인 경우 -> 신뢰 가능
                                                # 2) 목록 조회 주소(GET /api/v1/posts)인 경우 -> 응답 본문 내에 방금 생성한 resource_id가 포함되어 있어야 하며,
                                                #    그 resource_id 근처(예: 300자 이내)에 stored_payload가 발견되는지 검증하여 타 API 영향에 따른 오탐 차단
                                                is_legit_stored_xss = False
                                                if resource_id:
                                                    str_res_id = str(resource_id)
                                                    if str_res_id in resolved_path:  # 개별 리소스 조회 경로 매칭 완료
                                                        is_legit_stored_xss = True
                                                    elif str_res_id in get_res.text: # 목록형 응답
                                                        # resource_id 주변 400자 텍스트 파싱하여 검사
                                                        idx = get_res.text.find(str_res_id)
                                                        start_clip = max(0, idx - 100)
                                                        end_clip = min(len(get_res.text), idx + 350)
                                                        context_area = get_res.text[start_clip:end_clip]
                                                        if stored_payload in context_area:
                                                            is_legit_stored_xss = True
                                                else:
                                                    # 만약 resource_id 획득이 실패한 API의 경우, POST 경로와 GET 경로의 연관성이 높을 때만 폴백 인정
                                                    if api_url.rstrip("/").split("/")[-1] in get_url:
                                                        is_legit_stored_xss = True

                                                if is_legit_stored_xss:
                                                    get_content_type = get_res.headers.get("Content-Type", "").lower()
                                                    print(f"[STORED XSS] !!! CONFIRMED on {get_url} (Stored payload '{stored_payload}' reflected) !!!")
                                                    
                                                    response_params = infer_reflected_response_params(get_res, stored_payload)
                                                    custom_alerts.append({
                                                        "alert": "Stored Cross-Site Scripting (Stored XSS) Vulnerability",
                                                        "url": get_url,
                                                        "method": "GET",
                                                        "risk": "High",
                                                        "confidence": "High",
                                                        "param": target_param,
                                                        "reflected_response_params": response_params,
                                                        "attack": stored_payload,
                                                        "status_code": get_res.status_code,
                                                        "evidence": f"{method.upper()} {api_url} 저장 후 GET {get_url} 재조회 응답에 페이로드 '{stored_payload}'가 반사됨",
                                                        "custom_type": "40014",
                                                        "evidence_request": format_http_request(get_res.request),
                                                        "evidence_response": format_http_response(get_res),
                                                        "expected_status_code": get_res.status_code,
                                                        "expected_evidence_in_response": stored_payload,
                                                        "screenshot_on": "page_loaded",
                                                        "description": (
                                                            f"{method.upper()} {api_url}로 저장된 입력값이 GET {get_url} 재조회 시 HTML 인코딩 없이 그대로 반사되었습니다. "
                                                            f"이는 Stored(Persistent) XSS로 다른 사용자에게도 스크립트가 실행될 수 있습니다. "
                                                            f"(GET 응답 Content-Type: {get_content_type})"
                                                        )
                                                    })
                                                    break # 이 페이로드로 취약성이 확인되면 GET 순회 중단
                                        except Exception as get_err:
                                            print(f"[STORED XSS DEBUG] Broadcast GET fail on {get_url}: {get_err}")
                                            continue
    
                                    # Cleanup: 생성한 테스트 리소스 즉시 삭제 시도
                                    if resource_id:
                                        try:
                                            delete_url = f"{api_url.rstrip('/')}/{resource_id}"
                                            print(f"[Safety] skip cleanup DELETE {delete_url}: DELETE requests are disabled")
                                        except Exception:
                                            pass
                                else:
                                    print(
                                        f"[STORED XSS DEBUG] store failed -> {method.upper()} {api_url} "
                                        f"status {post_res.status_code}. Response: {summarize_response_for_log(post_res)}"
                                    )
                                            
                            except Exception as se:
                                print(f"Stored XSS 2-step scan payload trial fail for {api_url}: {se}")
                            
                    # (3) [SK 쉴더스 7-4] 보안 헤더 및 XSS 방어 설정 진단 (기본 GET/POST 전체 대상)
                    try:
                        headers = build_auth_headers(best_token, scan_account)
                        res = requests.request(method=method.upper(), url=api_url, headers=headers, timeout=4)
                        
                        x_content_type = res.headers.get("X-Content-Type-Options", "").lower()
                        content_type = res.headers.get("Content-Type", "").lower()
                        csp = res.headers.get("Content-Security-Policy", "")
                        security_header_findings = assess_security_headers(
                            res,
                            is_https=api_url.lower().startswith("https://"),
                        )
                        
                        # application/json이더라도 nosniff 헤더가 없고 응답 값이 브라우저에 의해 HTML로 마임 스니핑(MIME Sniffing)될 여지가 있는 경우 XSS 연계 위험
                        if "nosniff" not in x_content_type and "json" in content_type:
                            custom_alerts.append({
                                "alert": "Absence of Anti-MIME-Sniffing Header (X-Content-Type-Options: nosniff)",
                                "url": api_url,
                                "method": method.upper(),
                                "risk": "Low",
                                "confidence": "Medium",
                                "param": "X-Content-Type-Options",
                                "attack": "",
                                "status_code": res.status_code,
                                "evidence": f"응답 Content-Type이 '{content_type}'임에도 브라우저 차단용 X-Content-Type-Options: nosniff 헤더가 감지되지 않음",
                                "custom_type": "MIME_SNIFF_CUSTOM",
                                "evidence_request": format_http_request(res.request),
                                "evidence_response": format_http_response(res),
                                "description": (
                                    "API 응답에 'X-Content-Type-Options: nosniff' 헤더가 존재하지 않습니다. "
                                    "구형 브라우저 혹은 특정 상황에서 JSON 데이터를 HTML 문서인 것처럼 오해하여 자바스크립트를 임의 실행하는 XSS(크로스 사이트 스크립팅) 공격에 악용될 수 있습니다."
                                ),
                                "solution": "서버의 HTTP 응답 헤더에 'X-Content-Type-Options: nosniff'를 강제 적용하여 브라우저의 임의 형식 해석을 차단하세요."
                            })
                            
                        # Content-Security-Policy 부재 및 실효성 우회 진단
                        if not csp:
                            custom_alerts.append({
                                "alert": "Content Security Policy (CSP) Not Configured",
                                "url": api_url,
                                "method": method.upper(),
                                "risk": "Informational",
                                "confidence": "High",
                                "param": "Content-Security-Policy",
                                "attack": "",
                                "status_code": res.status_code,
                                "evidence": "응답 헤더에 콘텐츠 리소스 화이트리스트 통제 정책인 Content-Security-Policy 헤더가 정의되지 않음",
                                "custom_type": "90034", # CSP 부재에 매핑
                                "evidence_request": format_http_request(res.request),
                                "evidence_response": format_http_response(res),
                                "description": (
                                    "콘텐츠 보안 정책(CSP) 헤더가 설정되어 있지 않습니다. "
                                    "XSS 공격 등으로 악성 스크립트 유입 시 이를 차단할 방어선이 없는 상태입니다."
                                ),
                                "solution": "화면에 필요한 리소스 출처만 명시적으로 허용하는 Content-Security-Policy 헤더를 응답에 포함하세요."
                            })
                        else:
                            csp_lower = csp.lower()
                            # 고도화 5: 무용지물 CSP (Bypassable) 검사
                            bypass_indicators = []
                            if "unsafe-inline" in csp_lower:
                                bypass_indicators.append("unsafe-inline")
                            if "unsafe-eval" in csp_lower:
                                bypass_indicators.append("unsafe-eval")
                            if "* " in csp_lower or " *" in csp_lower or "http:" in csp_lower:
                                bypass_indicators.append("wildcard/insecure directive")
                                
                            if bypass_indicators:
                                custom_alerts.append({
                                    "alert": "Content Security Policy (CSP) Bypass Weakness",
                                    "url": api_url,
                                    "method": method.upper(),
                                    "risk": "Low",
                                    "confidence": "High",
                                    "param": "Content-Security-Policy",
                                    "attack": f"CSP Directive: {csp[:80]}...",
                                    "status_code": res.status_code,
                                    "evidence": f"CSP에 보안 우회 가능한 정책 선언 확인: {', '.join(bypass_indicators)}",
                                    "custom_type": "90034",
                                    "evidence_request": format_http_request(res.request),
                                    "evidence_response": format_http_response(res),
                                    "description": f"Content-Security-Policy 헤더가 응답에 존재하지만, 보안 우회를 허용하는 지시문({', '.join(bypass_indicators)})이 활성화되어 있어 스크립트 인젝션 차단 실효성이 결여되어 있습니다.",
                                    "solution": "CSP 정책에서 'unsafe-inline' 및 'unsafe-eval' 사용을 배제하고, 소스 출처 도메인을 명확하게 정의하여 와일드카드 사용을 금지하세요."
                                })
    
                        # 고도화 4: 쿠키 HttpOnly 및 Secure 옵션 분석 추가
                        set_cookie_headers = res.headers.get("Set-Cookie", res.headers.get("set-cookie", ""))
                        if set_cookie_headers:
                            # 콤마로 복수 쿠키 발급 시 쪼개서 분석
                            cookies = set_cookie_headers.split(",")
                            for cookie in cookies:
                                cookie_lower = cookie.lower()
                                if "httponly" not in cookie_lower:
                                    custom_alerts.append({
                                        "alert": "Cookie Missing HttpOnly Flag",
                                        "url": api_url,
                                        "method": method.upper(),
                                        "risk": "Low",
                                        "confidence": "High",
                                        "param": "Set-Cookie",
                                        "attack": "",
                                        "status_code": res.status_code,
                                        "evidence": f"Set-Cookie 헤더 내 쿠키: {cookie[:60].strip()}...",
                                        "custom_type": "COOKIE_HTTPONLY_CUSTOM",
                                        "evidence_request": format_http_request(res.request),
                                        "evidence_response": format_http_response(res),
                                        "description": "쿠키에 HttpOnly 플래그가 설정되어 있지 않아 악성 스크립트 실행(XSS) 시 브라우저 내 자바스크립트(`document.cookie`)에 의해 중요 토큰/세션 식별 정보가 손쉽게 유출될 수 있습니다.",
                                        "solution": "쿠키 발급 시 HttpOnly 플래그를 필수로 주입하여 클라이언트 스크립트 기반 쿠키 읽기 권한을 차단하십시오."
                                    })
                                if "secure" not in cookie_lower and api_url.lower().startswith("https://"):
                                    custom_alerts.append({
                                        "alert": "Cookie Missing Secure Flag over HTTPS",
                                        "url": api_url,
                                        "method": method.upper(),
                                        "risk": "Low",
                                        "confidence": "High",
                                        "param": "Set-Cookie",
                                        "attack": "",
                                        "status_code": res.status_code,
                                        "evidence": f"Set-Cookie 헤더 내 쿠키: {cookie[:60].strip()}...",
                                        "custom_type": "COOKIE_SECURE_CUSTOM",
                                        "evidence_request": format_http_request(res.request),
                                        "evidence_response": format_http_response(res),
                                        "description": "HTTPS 암호화 통신 환경에서 발급된 쿠키에 Secure 플래그가 누락되었습니다. 공격자가 암호화되지 않은 HTTP 경로로 강제 전환하거나 네트워크 스니핑을 유도할 때 자격 증명이 네트워크 상에 평문으로 유출될 우려가 있습니다.",
                                        "solution": "쿠키를 생성할 때 Secure 속성을 동반 선언하여 평문 HTTP 구간에서의 전송을 제한하세요."
                                    })
                        for header_finding in security_header_findings:
                            header_name = header_finding["header"]
                            if header_name in ["X-Content-Type-Options", "Content-Security-Policy"]:
                                continue
                            
                            # 각 헤더명에 대응되는 정밀 커스텀 키 매핑
                            if header_name == "Referrer-Policy":
                                c_type = "REFERRER_POLICY_CUSTOM"
                            elif header_name == "Permissions-Policy":
                                c_type = "PERMISSIONS_POLICY_CUSTOM"
                            elif header_name == "X-Frame-Options":
                                c_type = "X_FRAME_OPTIONS_CUSTOM"
                            elif header_name == "Strict-Transport-Security":
                                c_type = "HSTS_CUSTOM"
                            else:
                                c_type = "MIME_SNIFF_CUSTOM"
    
                            rem_info = KOREAN_REMEDIATIONS.get(c_type, {})
                            custom_alerts.append({
                                "alert": f"Security Header Weakness: {header_name}",
                                "url": api_url,
                                "method": method.upper(),
                                "risk": "Low",
                                "confidence": "High",
                                "param": header_name,
                                "attack": "",
                                "status_code": res.status_code,
                                "evidence": header_finding["message"],
                                "custom_type": c_type,
                                "evidence_request": format_http_request(res.request),
                                "evidence_response": format_http_response(res),
                                "description": rem_info.get("cause", header_finding["message"]),
                                "solution": rem_info.get("action_guide", f"Configure a safe {header_name} response header value.")
                            })
                    except Exception as xe:
                        print(f"Security header scan skip for {api_url}: {xe}")
    
                    # 이 엔드포인트에서 새로 추가된 모든 alert에 account_role 일괄 태깅
                    for _i in range(_alerts_snapshot, len(custom_alerts)):
                        custom_alerts[_i].setdefault("account_role", best_role)
    
        update_status(progress=90, message="결과 수집 및 리포트 생성 중...")
        
        # ZAP API 원본 Alert 수집
        raw_alerts = zap.core.alerts(baseurl=target_url, start=0, count=9999)
        
        # ZAP 원본 Alert 중 XSS 및 CSRF 관련 항목만 필터링 (기타 패시브 스캔 노이즈 제거)
        # 고도화 1-1: 단순 confidence가 "Low"라고 다 자르는 게 아니라, application/json + nosniff 조합인 경우(XSS 차단 성립)만 확정 오탐으로 간주하여 필터링함.
        allowed_plugin_ids = ["40012", "40014", "40016", "40017", "90034"]
        filtered_raw_alerts = []
        for a in raw_alerts:
            p_id = a.get("pluginId")
            if p_id in allowed_plugin_ids:
                if p_id in ["40012", "40014"] and a.get("confidence", "").lower() == "low":
                    # 상세 패킷 정보에서 실제 nosniff + json 여부 체크
                    msg_id = a.get("messageId")
                    is_safe_json_context = False
                    if msg_id:
                        try:
                            msg_detail = zap.core.message(msg_id)
                            res_header = msg_detail.get("responseHeader", "").lower()
                            if "application/json" in res_header and "nosniff" in res_header:
                                is_safe_json_context = True
                        except Exception:
                            pass
                    
                    if is_safe_json_context:
                        # 실행 불가 맥락이므로 오탐 차단
                        continue
                filtered_raw_alerts.append(a)
        
        # 수동 검증한 커스텀 취약점 항목(CSRF, XSS 보안헤더 누락 등) 병합
        all_raw_alerts = filtered_raw_alerts + custom_alerts
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # [중복 제거 및 그룹화 로직] 
        # - 일반 취약점: URL + Method + 취약점 종류(PluginId/CustomType)가 같으면 하나로 병합
        # - 보안 헤더 누락: 헤더 종류별로 1건만 대표 리포팅, 중복 URL 목록은 affected_urls에 누적
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        grouped_alerts = {}
        # 헤더 누락 계열: 전역 1건 (서버 전체 설정 버그)
        header_custom_types = {
            "REFERRER_POLICY_CUSTOM",
            "PERMISSIONS_POLICY_CUSTOM",
            "X_FRAME_OPTIONS_CUSTOM",
            "HSTS_CUSTOM",
            "MIME_SNIFF_CUSTOM",   # X-Content-Type-Options 누락
        }
        cors_reflection_types = {"CORS_ORIGIN_REFLECTION"}
        # 기타 전역 1건 타입 (동일 설정/구현 버그가 전체에 영향)
        global_single_types = {
            "6-1_ERR_DISCLOSE",           # 에러 정보 노출
            "90034",                       # CSP 부재 / CSP Bypass
            "COOKIE_HTTPONLY_CUSTOM",      # HttpOnly 누락
            "COOKIE_SECURE_CUSTOM",        # Secure 누락
            "COOKIE_SAMESITE_CUSTOM",      # SameSite=None
        }

        for a in all_raw_alerts:
            url = a.get("url", "")
            method = a.get("method", "GET")
            plugin_id = a.get("pluginId", "")
            custom_type = a.get("custom_type", "")
            account_role = a.get("account_role", "")
            key_id = custom_type if custom_type else plugin_id
            
            # 취약점 ID가 없으면 건너뜀
            if not key_id:
                continue

            # 고도화 2-1: 전역 1건 묶기 규칙
            if key_id in header_custom_types:
                unique_key = f"GLOBAL_HEADER_{key_id}"
            elif key_id in cors_reflection_types:
                unique_key = "GLOBAL_CORS_ORIGIN_REFLECTION"
            elif key_id in global_single_types:
                unique_key = f"GLOBAL_{key_id}"
            else:
                # ZAP 네이티브 alert 중 alert 이름 기준으로 전역 묶기
                alert_name = a.get("alert", "")
                if "Content Security Policy" in alert_name:
                    unique_key = "GLOBAL_ZAP_CSP"
                elif "X-Content-Type-Options" in alert_name or "Anti-MIME" in alert_name:
                    unique_key = "GLOBAL_ZAP_MIME_SNIFF"
                elif "Referrer-Policy" in alert_name or "Referrer Policy" in alert_name:
                    unique_key = "GLOBAL_ZAP_REFERRER"
                elif "Permissions-Policy" in alert_name or "Permissions Policy" in alert_name:
                    unique_key = "GLOBAL_ZAP_PERMISSIONS"
                elif "X-Frame-Options" in alert_name:
                    unique_key = "GLOBAL_ZAP_XFRAME"
                elif "Strict-Transport-Security" in alert_name or "HSTS" in alert_name:
                    unique_key = "GLOBAL_ZAP_HSTS"
                elif "Cookie" in alert_name and ("HttpOnly" in alert_name or "Secure" in alert_name or "SameSite" in alert_name):
                    unique_key = f"GLOBAL_ZAP_{alert_name.replace(' ', '_')[:40]}"
                elif custom_type == "40014" and a.get("cross_account_reader_role"):
                    reader_role = a.get("cross_account_reader_role", "")
                    param_name = a.get("param", "")
                    unique_key = f"{account_role}_{reader_role}_{method}_{url}_{key_id}_{param_name}"
                else:
                    param_name = a.get("param", "")
                    unique_key = f"{account_role}_{method}_{url}_{key_id}_{param_name}"
                
            param_name = a.get("param", "")
            
            if unique_key not in grouped_alerts:
                grouped_alerts[unique_key] = a
                grouped_alerts[unique_key]["occurrence_count"] = 1
                grouped_alerts[unique_key]["affected_parameters"] = [param_name] if param_name else []
                grouped_alerts[unique_key]["account_roles"] = [account_role] if account_role else []
                if account_role:
                    grouped_alerts[unique_key]["account_role"] = account_role
                # affected_urls 필드 초기화 및 추가
                grouped_alerts[unique_key]["affected_urls"] = [f"{method} {url}"]
                # 커스텀 패킷 증거 바인딩
                grouped_alerts[unique_key]["evidence_request"] = a.get("evidence_request", "")
                grouped_alerts[unique_key]["evidence_response"] = a.get("evidence_response", "")
                # 성공 페이로드 초기화
                init_payloads = a.get("successful_attack_payloads", [])
                if not init_payloads and a.get("attack"):
                    init_payloads = [a.get("attack")]
                grouped_alerts[unique_key]["successful_attack_payloads"] = list(init_payloads)
            else:
                grouped_alerts[unique_key]["occurrence_count"] += 1
                current_url = f"{method} {url}"
                if current_url not in grouped_alerts[unique_key]["affected_urls"]:
                    grouped_alerts[unique_key]["affected_urls"].append(current_url)
                    
                if param_name and param_name not in grouped_alerts[unique_key]["affected_parameters"]:
                    grouped_alerts[unique_key]["affected_parameters"].append(param_name)

                account_roles = grouped_alerts[unique_key].setdefault("account_roles", [])
                if account_role and account_role not in account_roles:
                    account_roles.append(account_role)
                    grouped_alerts[unique_key]["account_role"] = ", ".join(account_roles)
                    
                # 증거 패킷 업데이트 (대표값 확보)
                if not grouped_alerts[unique_key]["evidence_request"] and a.get("evidence_request"):
                    grouped_alerts[unique_key]["evidence_request"] = a.get("evidence_request")
                    grouped_alerts[unique_key]["evidence_response"] = a.get("evidence_response")
                    
                # 성공 페이로드 리스트 병합 (중복 제거)
                existing_payloads = grouped_alerts[unique_key].get("successful_attack_payloads", [])
                new_payloads = a.get("successful_attack_payloads", [])
                if not new_payloads and a.get("attack"):
                    new_payloads = [a.get("attack")]
                combined = list(set(existing_payloads + new_payloads))
                try:
                    grouped_alerts[unique_key]["successful_attack_payloads"] = sorted(combined, key=lambda p: XSS_PAYLOADS.index(p) if p in XSS_PAYLOADS else 999)
                except Exception:
                    grouped_alerts[unique_key]["successful_attack_payloads"] = combined

                    
        # 병합된 Alert 리스트 추출
        print(f"[DEBUG] custom_alerts: {len(custom_alerts)}건")
        print(f"[DEBUG] filtered_raw_alerts: {len(filtered_raw_alerts)}건")
        print(f"[DEBUG] all_raw_alerts: {len(all_raw_alerts)}건")
        print(f"[DEBUG] grouped_alerts: {len(grouped_alerts)}건")
        for k, v in grouped_alerts.items():
            print(f"  - {k}: {v.get('alert','')[:50]}")
        final_alerts = list(grouped_alerts.values())

        # 취약점 분류 매핑 후 구조화
        re_mapped_alerts = []
        for alert in final_alerts:
            alert_name = alert.get("alert", "")
            writer_role = alert.get("cross_account_writer_role")
            reader_role = alert.get("cross_account_reader_role")
            if alert.get("custom_type") == "40014" and writer_role and reader_role:
                suffix = f" (작성: {writer_role}, 열람: {reader_role})"
                if suffix not in alert_name:
                    alert_name += suffix
                    
            param_name = alert.get("param", "")
            attack_val = alert.get("attack", "")
            description = alert.get("description", "")
            plugin_id = alert.get("pluginId", "")
            custom_type = alert.get("custom_type", "")
            key_id = custom_type if custom_type else plugin_id
            
            # ZAP 기본 Alert이고 messageId가 존재하는 경우, 실제 HTTP 패킷 조회
            evidence_req = alert.get("evidence_request", "")
            evidence_res = alert.get("evidence_response", "")
            msg_id = alert.get("messageId")
            
            status_code = alert.get("status_code", 0)
            if msg_id and not evidence_req and not evidence_res:
                try:
                    msg_detail = zap.core.message(msg_id)
                    if msg_detail:
                        req_header = msg_detail.get("requestHeader", "").strip()
                        req_body = msg_detail.get("requestBody", "").strip()
                        res_header = msg_detail.get("responseHeader", "").strip()
                        res_body = msg_detail.get("responseBody", "").strip()
                        
                        evidence_req = f"{req_header}\n\n{req_body}".strip()
                        evidence_res = f"{res_header}\n\n{res_body}".strip()
                        
                        # 응답 헤더로부터 상태 코드 추출 시도 (예: "HTTP/1.1 500")
                        try:
                            first_line = res_header.split("\r\n")[0] if res_header else ""
                            parts = first_line.split(" ")
                            if len(parts) > 1:
                                status_code = int(parts[1])
                        except Exception:
                            pass
                except Exception as me:
                    print(f"Failed to fetch HTTP message detail for alert (msg_id: {msg_id}): {me}")
            
            # 헤더 정보가 이미 있는 경우 파싱
            if not status_code and evidence_res:
                try:
                    first_line = evidence_res.split("\n")[0].strip()
                    parts = first_line.split(" ")
                    if len(parts) > 1:
                        status_code = int(parts[1])
                except Exception:
                    pass
                    
            # 한글 대응 조치 가이드 바인딩
            ko_info = KOREAN_REMEDIATIONS.get(key_id, {})
            
            vuln_id, vuln_type, severity, vuln_desc = classify_alert(
                alert_name,
                param_name,
                attack_val,
                description,
                custom_type=custom_type or plugin_id,
            )
            
            # 만약 ZAP에서 내려온 기본 evidence가 비어있고 XSS 등 반사 유형이라면 응답 바디에서 공격 페이로드 전후 맥락을 찾아 증거로 설정
            alert_evidence = alert.get("evidence", "")
            if not alert_evidence and attack_val and attack_val in evidence_res:
                try:
                    idx = evidence_res.find(attack_val)
                    start_idx = max(0, idx - 80)
                    end_idx = min(len(evidence_res), idx + len(attack_val) + 80)
                    context_clip = evidence_res[start_idx:end_idx]
                    alert_evidence = f"... {context_clip.strip()} ..."
                except Exception:
                    pass
            
            # ── 정탐/오탐 자동 판별 분석 필드 추가 ──
            val_status = "True Positive"
            val_reason = "동작 검증 완료"

            k_type = custom_type or plugin_id
            if k_type == "40014" or k_type == "STORED_XSS_CUSTOM":
                val_status = "True Positive"
                val_reason = "POST 요청을 통한 데이터 저장 및 GET 재조회 응답에서의 영구 스크립트 유출 확인 (정탐). 단, 실제 브라우저 렌더링 시 프론트엔드(React/Vue 등)의 자동 이스케이프 설정에 따라 공격 성공 여부가 달라질 수 있으므로 프론트 연동 테스트를 통한 최종 확정이 필요합니다."
            elif k_type == "CSRF_CUSTOM":
                val_status = "True Positive"
                val_reason = "조작되거나 누락된 Referer/Token 조건에서 중요 상태 변경 API 호출이 수용됨 (정탐). 단, 실제 브라우저 환경의 SameSite 쿠키 정책 및 CORS/Origin 설정에 따라 공격 발화 여부가 달라질 수 있으므로 추가 확인이 필요합니다."
            elif k_type == "CORS_ORIGIN_REFLECTION":
                val_status = "True Positive"
                val_reason = "요청에 실어 보낸 임의의 공격용 Origin 헤더가 ACAO 응답 헤더에 그대로 반사되고 Credentials가 허용됨 (정탐)"
            elif k_type == "40012":
                res_ct = alert.get("Content-Type", "").lower() or ("json" if "application/json" in evidence_res.lower() else "")
                if "json" in res_ct or "application/json" in evidence_res.lower():
                    val_status = "Potential"
                    val_reason = "API 응답(JSON) 내에 페이로드 에코백 확인. React/Vue 등의 이스케이프 설정에 따라 실제 실행 가능성이 달라짐 (잠재적 취약)"
                else:
                    val_status = "True Positive"
                    val_reason = "HTML 본문 내에 인코딩 처리가 생략된 스크립트 문법이 그대로 반사되어 즉시 런타임 실행 가능함 (정탐)"
            elif k_type == "DOM_XSS_SUSPECT":
                val_status = "Suspected"
                val_reason = "정적 텍스트 분석 상 브라우저 입력 소스(Source) 및 취약 함수(Sink)의 동시 노출 확인. 동적 발화 검증 필요 (의심)"
            elif k_type in ["REFERRER_POLICY_CUSTOM", "PERMISSIONS_POLICY_CUSTOM", "MIME_SNIFF_CUSTOM", "GLOBAL_ZAP_CSP", "GLOBAL_ZAP_MIME_SNIFF", "GLOBAL_ZAP_REFERRER", "GLOBAL_ZAP_PERMISSIONS", "GLOBAL_ZAP_XFRAME", "90034"]:
                val_status = "True Positive"
                val_reason = "HTTP 응답 헤더 내 보안 설정 검증 결과 누락 또는 취약하게 바인딩되어 있음 (정탐)"

            re_mapped_alerts.append({
                "vuln_id": vuln_id,
                "vuln_type": vuln_type,
                "severity": severity,
                "vuln_description": vuln_desc,
                "validation_status": val_status,
                "validation_reason": val_reason,
                "alert": alert_name,
                "url": alert.get("url", ""),
                "method": alert.get("method", "GET"),
                "risk": alert.get("risk", "Medium"),
                "confidence": alert.get("confidence", "Medium"),
                "param": param_name,
                "attack": attack_val,
                "status_code": status_code,
                "evidence": alert_evidence,
                "evidence_request": evidence_req,
                "evidence_response": evidence_res,
                "description": description,
                "occurrence_count": alert.get("occurrence_count", 1),
                "account_role": alert.get("account_role", ""),
                "account_roles": alert.get("account_roles", []),
                "affected_parameters": alert.get("affected_parameters", []),
                "reflected_response_params": alert.get("reflected_response_params", []),
                "affected_urls": alert.get("affected_urls", []),
                "auth_acceptance_mode": alert.get("auth_acceptance_mode", ""),
                "auth_acceptance_statuses": alert.get("auth_acceptance_statuses", {}),
                "cookie_source": alert.get("cookie_source", ""),
                "cross_account_writer_role": alert.get("cross_account_writer_role", ""),
                "cross_account_reader_role": alert.get("cross_account_reader_role", ""),
                "cross_account_write_url": alert.get("cross_account_write_url", ""),
                "cross_account_read_url": alert.get("cross_account_read_url", ""),
                "remediation_summary": ko_info.get("summary", ""),
                "remediation_cause": ko_info.get("cause", "").replace("{param}", param_name),
                "remediation_guide": ko_info.get("action_guide", ""),
                "remediation_code": ko_info.get("code_example", "")
            })
            
        # [요구사항 반영] XSS 및 CSRF 관련 취약점만 리포팅하도록 필터링
        xss_csrf_alerts = []
        for a in re_mapped_alerts:
            v_type = a.get("vuln_type", "").lower()
            a_name = a.get("alert", "").lower()
            if "xss" in v_type or "csrf" in v_type or "xss" in a_name or "csrf" in a_name or "cross-site" in a_name:
                xss_csrf_alerts.append(a)
        
        re_mapped_alerts = xss_csrf_alerts

        update_status(total_alerts=len(re_mapped_alerts))
        
        # 결과 파일 저장
        role = "web_ui"
        result_dir = result_dir_override or "results"
        os.makedirs(result_dir, exist_ok=True)
        summary_filename = f"{result_dir}/zap_report_summary_{role}.json"
        
        with open(summary_filename, "w", encoding="utf-8") as f:
            json.dump(re_mapped_alerts, f, ensure_ascii=False, indent=4)
            
        # JSONC (주석이 포함된 상세 리포트) 추가 생성 로직
        filtered_jsonc_filename = f"{result_dir}/zap_report_summary_{role}_filtered.jsonc"
        try:
            # 유효한 경고 전체 수집 (False Positive 제외하고 Informational 등급도 정상 포함)
            meaningful_alerts = [a for a in re_mapped_alerts if a.get("severity") != "-" and a.get("risk") != "False Positive"]
            
            # 상태별 건수 통계 계산
            tp_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "True Positive")
            pot_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "Potential")
            susp_count = sum(1 for a in meaningful_alerts if a.get("validation_status") == "Suspected")
            fp_count = len(re_mapped_alerts) - len(meaningful_alerts)

            with open(filtered_jsonc_filename, "w", encoding="utf-8") as jf:
                jf.write("// =====================================================================\n")
                jf.write("// ZAP(OWASP) 및 커스텀 스캔 결과 리포트 - 상세 취약점 필터링본 (.jsonc)\n")
                jf.write(f"// [취약점 통계]\n")
                jf.write(f"//  - 총 발견 취약점: {len(meaningful_alerts)}개\n")
                jf.write(f"//  - 1. 정탐 확정 (True Positive): {tp_count}개\n")
                jf.write(f"//  - 2. 잠재적 취약 (Potential): {pot_count}개 (프론트엔드 방어 여부에 따라 유동적)\n")
                jf.write(f"//  - 3. 취약점 의심 (Suspected): {susp_count}개 (동적/추가 검증 권장)\n")
                jf.write(f"//  - 4. 오탐 필터링 (False Positive): {fp_count}개 차단 완료\n")
                jf.write("// =====================================================================\n")
                jf.write("[\n")
                
                for idx, a in enumerate(meaningful_alerts):
                    jf.write("    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                    writer_role = a.get("cross_account_writer_role")
                    reader_role = a.get("cross_account_reader_role")
                    roles_str = f" (작성: {writer_role}, 열람: {reader_role})" if writer_role and reader_role else ""
                    jf.write(f"    // 【{idx + 1}번 항목】 공격 분류: {a.get('vuln_id')} - {a.get('vuln_type')}{roles_str} (위험 등급: {a.get('risk')})\n")
                    jf.write(f"    // 💡 위협 설명: {a.get('vuln_description')}\n")
                    
                    guide_lines = a.get("remediation_guide", "").split("\n")
                    if guide_lines and guide_lines[0]:
                        jf.write("    // 🛠️ 조치 가이드:\n")
                        for gl in guide_lines:
                            jf.write(f"    //    {gl}\n")
                            
                    jf.write("    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                    
                    # JSON 객체 직렬화 후 들여쓰기 조절
                    item_json = json.dumps(a, ensure_ascii=False, indent=12)
                    # 괄호 시작과 끝 정렬을 깔끔하게 맞춤
                    item_json_formatted = "    " + item_json.strip()
                    
                    jf.write(item_json_formatted)
                    if idx < len(meaningful_alerts) - 1:
                        jf.write(",\n")
                    else:
                        jf.write("\n")
                        
                jf.write("]\n")
            print(f"[+] JSONC report generated successfully at {filtered_jsonc_filename}")
        except Exception as je:
            print(f"[-] Fail to generate JSONC report: {je}")
            
        update_status(is_running=False, progress=100, message="스캔이 성공적으로 완료되었습니다.", result_file=summary_filename)
        print(f"[+] Scan completed. Report saved to {summary_filename}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        update_status(is_running=False, message=f"스캔 오류 발생: {str(e)}")







