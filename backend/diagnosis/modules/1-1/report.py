"""Report mapping and remediation text for ARGUS 1-1."""

def classify_alert(alert_name, param_name, attack_val, description, custom_type=None):
    an = (alert_name or "").lower()
    custom_type = custom_type or ""

    if custom_type == "40012":
        return "1-1", "Reflected XSS", "중요", "입력값이 응답 본문에 실행 가능한 형태로 반사되어 브라우저에서 스크립트가 실행될 수 있습니다."
    if custom_type in {"40014", "STORED_XSS_CUSTOM"}:
        return "1-1", "Stored XSS", "중요", "저장된 입력값이 이후 조회 응답에서 실행 가능한 형태로 다시 노출됩니다."
    if custom_type in {"DOM_XSS_CUSTOM", "DOM_XSS_SUSPECT"}:
        severity = "참고" if custom_type == "DOM_XSS_SUSPECT" else "중요"
        return "1-1", "DOM XSS", severity, "클라이언트 DOM 처리 경로에서 사용자 입력이 실행 가능한 코드로 처리될 수 있습니다."
    if custom_type == "CSRF_CUSTOM":
        return "1-1", "CSRF", "중요", "Referer/Origin, CSRF 토큰, SameSite 방어가 충분히 동작하지 않아 상태 변경 요청이 위조될 수 있습니다."
    if custom_type == "CORS_ORIGIN_REFLECTION":
        return "1-1", "CORS Origin Reflection", "중요", "임의 Origin이 허용되어 인증된 API 응답이 외부 출처에서 접근될 수 있습니다."
    if any(k in an for k in ["cross-site", "cross site", "xss", "csrf"]):
        return "1-1", "XSS / CSRF 공격 가능성", "중요", "입력값 처리 또는 요청 출처 검증이 부족해 XSS/CSRF 위험이 존재합니다."
    return "1-1", "XSS / CSRF 검증 대상", "참고", "1-1 범위에서 분류되지 않은 항목입니다."

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
    "CSRF_CUSTOM": {
        "summary": "CSRF defense validation failed.",
        "cause": "At least two defenses among Origin/Referer validation, anti-CSRF token validation, and SameSite cookie protection are not working sufficiently.",
        "action_guide": (
            "1. Validate Origin or Referer on state-changing APIs. "
            "2. Issue an unpredictable anti-CSRF token and verify it on each state-changing request. "
            "3. When session cookies are used, set SameSite=Lax or SameSite=Strict."
        ),
        "code_example": (
            "http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())); "
            "Set-Cookie: SESSION=...; HttpOnly; Secure; SameSite=Lax"
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
    }
}

# ── 다중 XSS 페이로드 목록 (WAF/필터 우회 변형 포함) ───────────────────────────────────
