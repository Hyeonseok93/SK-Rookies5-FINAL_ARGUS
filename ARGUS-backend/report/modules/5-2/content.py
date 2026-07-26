"""5-2 결과서에 사용하는 한글 라벨·탐지 기법 매핑·대응방안 텍스트

진단 스캐너(diagnosis/modules/5-2/pii_rules.py)가 만들어 내는 rule_id / category /
direction 값을 사람이 읽을 수 있는 한글로 바꾸고, 각 탐지 기법이 실제로 무엇을
어떻게 점검했는지 설명하는 문구를 제공한다.
"""

from __future__ import annotations

# ── 심각도 라벨 ────────────────────────────────────────────────────────────
SEVERITY_KO: dict[str, str] = {
    "high": "높음",
    "medium": "중간",
    "low": "낮음",
    "info": "정보",
}

# ── 개인정보 유형(category) 라벨 ──────────────────────────────────────────
CATEGORY_KO: dict[str, str] = {
    "email": "이메일",
    "phone": "전화번호",
    "name": "이름",
    "rrn": "주민등록번호",
    "passport": "여권번호",
    "payment": "카드번호",
    "account": "계좌번호",
    "bank": "은행명",
    "path": "경로·구조",
    "transport": "평문 전송(HTTP)",
}

# ── 노출 위치(direction) 라벨 ─────────────────────────────────────────────
DIRECTION_KO: dict[str, str] = {
    "request_body": "요청 본문",
    "response_body": "응답 본문",
    "transport": "전송 계층",
    "request_url": "요청 URL",
    "query": "URL 파라미터",
}

# ── rule_id → 탐지 기법 식별자 ────────────────────────────────────────────
# 실제 발견된 rule_id 를 아래 4가지 탐지 기법 중 하나로 매핑한다.
RULE_TO_TECHNIQUE: dict[str, str] = {
    "email_plain": "plaintext_pii_scan",
    "phone_plain": "plaintext_pii_scan",
    "rrn_plain": "plaintext_pii_scan",
    "passport_plain": "plaintext_pii_scan",
    "card_plain": "plaintext_pii_scan",
    "account_plain": "plaintext_pii_scan",
    "korean_name_plain": "plaintext_pii_scan",
    "bank_name_plain": "plaintext_pii_scan",
    "path_structure": "path_structure_scan",
    "http_plain_sensitive": "plaintext_transport_scan",
}

# ── 탐지 기법 설명 ────────────────────────────────────────────────────────
# key: 탐지 기법 식별자, value: {title, summary, detail}
TECHNIQUES: dict[str, dict[str, str]] = {
    "plaintext_pii_scan": {
        "title": "평문 개인정보 패턴 스캔",
        "summary": "요청·응답 본문(JSON)을 재귀적으로 순회하며 개인정보가 마스킹 없이 노출되는지 탐지",
        "detail": (
            "API 요청 본문과 응답 본문(JSON)을 필드 단위로 모두 펼쳐, 이메일·전화번호·"
            "주민등록번호·여권번호·카드번호·계좌번호·한글 이름·은행명 등이 마스킹(예: "
            "010-****-1234)이나 암호화 없이 평문으로 담겨 있는지 정규식·체크섬(주민번호 "
            "검증식, 카드번호 Luhn)으로 검증합니다. argus-probe@example.com 처럼 점검 "
            "도구가 주입한 테스트 값은 노출로 보지 않도록 예외 처리합니다."
        ),
    },
    "path_structure_scan": {
        "title": "경로·파일구조 노출 스캔",
        "summary": "URL 파라미터·값 안에 서버 디렉터리·파일 경로 구조가 노출되는지 탐지",
        "detail": (
            "요청 URL의 쿼리스트링·경로 세그먼트와 응답 값에 /etc/passwd, /var/www/, "
            ".env, ../ 같은 서버 내부 디렉터리·파일구조 문자열이 그대로 노출되는지 "
            "점검합니다. 공격자가 내부 구조를 유추할 수 있는 단서가 되므로 별도로 표시합니다."
        ),
    },
    "plaintext_transport_scan": {
        "title": "평문(HTTP) 전송 탐지",
        "summary": "개인정보를 담은 요청·응답이 HTTPS 없이 HTTP 평문으로 전송되는지 탐지",
        "detail": (
            "개인정보가 포함된 요청·응답이 TLS(HTTPS)가 아닌 HTTP 평문 구간으로 오가는지 "
            "전송 계층(transport)을 확인합니다. 평문 전송은 통신 구간에서 도청·변조에 "
            "노출되므로 SSL/TLS 적용이 필요합니다."
        ),
    },
}

# 결과서에 항상 소개하는 공통 프로빙 방식(어떤 인증 상태로 테스트했는지)
PROBING_OVERVIEW = {
    "title": "오리진 스코프 다중 인증 프로빙",
    "summary": "익명 + 다수 로그인 계정 세션으로 동일 엔드포인트를 반복 요청해 인증 상태별 노출을 비교",
    "detail": (
        "Attack Surface에 등록한 API 인벤토리 전체를 대상으로, 비로그인(익명) 상태와 "
        "테스트 계정 로그인 세션을 각각 적용하여 동일 엔드포인트를 반복 호출합니다. "
        "httpx 엔진으로 실제 요청을 보내고 돌아온 요청·응답 값을 위 탐지 기법으로 "
        "분석하므로, 어떤 권한에서 어떤 개인정보가 노출되는지까지 확인할 수 있습니다."
    ),
}

# ── SK 가이드라인 5-2 대응방안 ────────────────────────────────────────────
REMEDIATION_TITLE = "대응방안"
REMEDIATION_PARAGRAPHS: list[str] = [
    (
        "URL 주소에서 파라미터 값은 누구나 쉽게 확인 가능하므로 디렉터리, 파일구조, "
        "개인정보, 사용자 식별 값, 결제정보 등의 중요한 값은 노출되지 않도록 해야 합니다."
    ),
    (
        "부득이하게 파라미터 값에 디렉터리, 파일구조, 개인정보, 결제정보 등과 같은 "
        "중요한 값이 포함되어야 한다면 암호화를 하여 확인할 수 없는 문자를 사용하거나 "
        "직접적인 값이 아닌 간접적인 값을 사용하여 실제 값에 접근하도록 합니다."
    ),
    (
        "국내외에서 권고하는 암호 알고리즘(KISA 「암호 알고리즘 및 키 길이 이용 안내서」)에 "
        "따라 신용카드번호, 휴대폰번호 등 개인정보와 비밀번호, 바이오정보 등 인증정보를 "
        "정보통신망 외부로 송·수신할 경우에는 SEED 128bit 이상의 보안강도를 가진 암호화 "
        "알고리즘을 통해 암호화하여 전송하거나 SSL을 적용하여 통신구간 데이터의 안전성을 "
        "확보하여야 합니다."
    ),
    (
        "전자서명, 키 공유, 메시지 암·복호화 등에 사용하는 경우 RSASSA-PSS 2048bit 이상의 "
        "보안강도를 가진 암호화 알고리즘을 사용해야 합니다."
    ),
]


def severity_ko(value: str | None) -> str:
    return SEVERITY_KO.get((value or "").lower(), value or "-")


def category_ko(value: str | None) -> str:
    return CATEGORY_KO.get((value or "").lower(), value or "-")


def direction_ko(value: str | None) -> str:
    return DIRECTION_KO.get((value or "").lower(), value or "-")
