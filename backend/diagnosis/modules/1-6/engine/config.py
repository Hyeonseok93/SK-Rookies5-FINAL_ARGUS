# =============================================================================
# config.py  ─  ARGUS W-1-6 범용 진단 엔진 v3 전역 설정
# =============================================================================

import os


class Config:
    # 대상 서버
    TARGET_URL: str = os.getenv("ARGUS_TARGET", "http://localhost:8080")

    # UI 로그인 및 화면 캡처용 대상 서버 (프론트엔드 분리 아키텍처 지원)
    UI_TARGET_URL: str = os.getenv("ARGUS_UI_TARGET", "")

    # Swagger 명세서 경로 (파일 또는 URL)
    API_SPEC: str = os.getenv("ARGUS_API_SPEC", "swagger.json")
    LOGIN_SPEC: str = os.getenv("ARGUS_LOGIN_SPEC", "")
    LOGIN_TARGET: str = os.getenv("ARGUS_LOGIN_TARGET", "")
    LOGIN_PATH: str = os.getenv("ARGUS_LOGIN_PATH", "")

    # 역할별 계정 {"admin": "pass", "user": "pass2"}
    # CLI --roles 인수로 덮어씀
    ROLES: dict = {}

    # 역할별 비밀번호 (JWT 갱신 시 재로그인에 사용)
    ROLE_PASSWORDS: dict = {}

    # ZAP
    ZAP_HOST: str = os.getenv("ZAP_HOST", "localhost")
    ZAP_PORT: int = int(os.getenv("ZAP_PORT", "8090"))
    ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "changeme")
    USE_ZAP_PROXY: bool = os.getenv("USE_ZAP_PROXY", "true").lower() in ("1", "true", "yes", "on")

    @property
    def ZAP_PROXY_URL(self) -> str:
        return f"http://{self.ZAP_HOST}:{self.ZAP_PORT}"

    @property
    def PROXIES(self) -> dict:
        if not self.USE_ZAP_PROXY:
            return {}
        p = self.ZAP_PROXY_URL
        return {"http": p, "https": p}

    # Selenium
    CHROME_DEBUG_PORT: int = int(os.getenv("CHROME_DEBUG_PORT", "9222"))
    SELENIUM_TIMEOUT: int = int(os.getenv("SELENIUM_TIMEOUT", "15"))
    LOGIN_MAX_RETRY: int = 3

    # Fuzzer
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "10"))
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "5"))
    JWT_REFRESH_THRESHOLD: int = int(os.getenv("JWT_REFRESH_THRESHOLD", "3"))
    SLOW_RESPONSE_THRESHOLD: float = float(os.getenv("SLOW_RESPONSE_SEC", "5.0"))
    DELAY_BETWEEN_REQUESTS: float = float(os.getenv("DELAY_BETWEEN_REQUESTS", "0.15"))
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "2"))
    MAX_TOTAL_REQUESTS: int = int(os.getenv("MAX_TOTAL_REQUESTS", "0"))
    MAX_REQUESTS_PER_ENDPOINT: int = int(os.getenv("MAX_REQUESTS_PER_ENDPOINT", "0"))
    CIRCUIT_BREAKER_FAILURES: int = int(os.getenv("CIRCUIT_BREAKER_FAILURES", "3"))
    CIRCUIT_BREAKER_COOLDOWN_SEC: float = float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SEC", "30"))
    STOP_ON_SERVER_DOWN: bool = os.getenv("STOP_ON_SERVER_DOWN", "false").lower() in ("1", "true", "yes", "on")

    # ZAP 스캔
    SPIDER_TIMEOUT: int = int(os.getenv("SPIDER_TIMEOUT_SEC", "120"))
    ACTIVE_SCAN_TIMEOUT_MIN: int = int(os.getenv("ACTIVE_SCAN_TIMEOUT_MIN", "60"))
    SCAN_POLICY_NAME: str = "ARGUS_W16_LargeDataInjection"
    W16_RULE_IDS: list = [
        "20010", "20012", "20014",
        "30001", "30002",
        "40008", "40032", "40034",
        "90019", "90034",
    ]

    # 출력
    OUTPUT_DIR: str = os.getenv("OUTPUT_DIR", "./output")
    REQUEST_TEMPLATES: str = os.getenv("ARGUS_REQUEST_TEMPLATES", "")

    # 민감 키워드
    SENSITIVE_KEYWORDS: list = [
        "stack trace", "stacktrace", "traceback",
        "at com.", "at java.", "at org.",
        "NullPointerException", "RuntimeException",
        "IndexOutOfBoundsException",
        "SQL syntax", "mysql_fetch", "ORA-", "pg_query", "sqlite3",
        "/etc/passwd", "/var/www", "C:\\Windows",
        "password", "secret", "api_key", "token",
        "OutOfMemoryError", "MemoryError", "heap space", "GC overhead",
    ]

    # 크롤링 경로 (Swagger 파싱 실패 시 폴백)
    CRAWL_PATHS: list = [
        "/", "/api/v1/users", "/api/v1/orders", "/api/v1/products",
        "/api/v1/search", "/api/v1/upload", "/api/v1/config",
        "/api/v1/admin", "/dashboard", "/admin",
    ]

    def validate(self):
        assert self.TARGET_URL.startswith("http"), "TARGET_URL 은 http:// 로 시작해야 합니다."
        assert 1 <= self.ZAP_PORT <= 65535, "ZAP_PORT 범위 오류"
        return True

# =============================================================================
# KISA 주통기 웹 취약점 항목 코드 (08.Web 섹션 28개)
# =============================================================================
# =============================================================================
# KISA 코드 → CWE / OWASP Top 10 2021 매핑
# 수집된 finding에 cwe, owasp 필드를 자동 주입하는 데 사용됨
# =============================================================================
KISA_TO_CWE_OWASP: dict = {
    # KISA코드: ([cwe_id_list], owasp_id)
    "BO": (["CWE-119", "CWE-120", "CWE-121", "CWE-122"], "A04:2021"),
    "FS": (["CWE-134"],                                    "A03:2021"),
    "LI": (["CWE-90"],                                     "A03:2021"),
    "OC": (["CWE-77", "CWE-78"],                          "A03:2021"),
    "SI": (["CWE-89"],                                     "A03:2021"),
    "SS": (["CWE-97"],                                     "A03:2021"),
    "XI": (["CWE-91"],                                     "A03:2021"),
    "DI": (["CWE-200", "CWE-548"],                        "A05:2021"),
    "IL": (["CWE-200", "CWE-209"],                        "A02:2021"),
    "CS": (["CWE-79", "CWE-80"],                          "A03:2021"),
    "XS": (["CWE-79", "CWE-80", "CWE-87"],               "A03:2021"),
    "BF": (["CWE-521"],                                    "A07:2021"),
    "IA": (["CWE-287", "CWE-306"],                        "A07:2021"),
    "PR": (["CWE-640"],                                    "A07:2021"),
    "CF": (["CWE-352"],                                    "A01:2021"),
    "SE": (["CWE-330", "CWE-340"],                        "A07:2021"),
    "IN": (["CWE-285", "CWE-862"],                        "A01:2021"),
    "SC": (["CWE-613"],                                    "A07:2021"),
    "SF": (["CWE-384"],                                    "A07:2021"),
    "AU": (["CWE-307", "CWE-799"],                        "A07:2021"),
    "PV": (["CWE-840"],                                    "A04:2021"),
    "FU": (["CWE-434"],                                    "A05:2021"),
    "FD": (["CWE-22", "CWE-36"],                          "A01:2021"),
    "AE": (["CWE-306", "CWE-862"],                        "A01:2021"),
    "PT": (["CWE-22", "CWE-23", "CWE-36"],               "A01:2021"),
    "PL": (["CWE-200"],                                    "A02:2021"),
    "SN": (["CWE-319", "CWE-311"],                        "A02:2021"),
    "CC": (["CWE-565", "CWE-614"],                        "A07:2021"),
}

# OWASP Top 10 2021 전체 카테고리 정의
OWASP_TOP10_2021: dict = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

KISA_WEB_ITEMS = {
    "BO": ("버퍼 오버플로우",              "상"),
    "FS": ("포맷 스트링",                  "상"),
    "LI": ("LDAP 인젝션",                  "상"),
    "OC": ("운영체제 명령 실행",            "상"),
    "SI": ("SQL 인젝션",                    "상"),
    "SS": ("SSI 인젝션",                    "상"),
    "XI": ("XPath 인젝션",                  "상"),
    "DI": ("디렉터리 인덱싱",              "상"),
    "IL": ("정보 누출",                     "상"),
    "CS": ("악성 콘텐츠",                  "상"),
    "XS": ("크로스사이트 스크립팅",        "상"),
    "BF": ("약한 문자열 강도",             "상"),
    "IA": ("불충분한 인증",                 "상"),
    "PR": ("취약한 패스워드 복구",          "상"),
    "CF": ("크로스사이트 리퀘스트 변조",   "상"),
    "SE": ("세션 예측",                     "상"),
    "IN": ("불충분한 인가",                 "상"),
    "SC": ("불충분한 세션 만료",            "상"),
    "SF": ("세션 고정",                     "상"),
    "AU": ("자동화 공격",                  "상"),
    "PV": ("프로세스 검증 누락",            "상"),
    "FU": ("파일 업로드",                  "상"),
    "FD": ("파일 다운로드",                "상"),
    "AE": ("관리자 페이지 노출",            "상"),
    "PT": ("경로 추적",                     "상"),
    "PL": ("위치 공개",                     "상"),
    "SN": ("데이터 평문 전송",              "상"),
    "CC": ("쿠키 변조",                     "상"),
}
