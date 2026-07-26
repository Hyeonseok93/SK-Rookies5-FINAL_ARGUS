"""Detect unmasked sensitive data in HTTP request/response values (5-2)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlparse

_RE_FLAGS = re.IGNORECASE | re.MULTILINE

# Values from ARGUS probe kit — not customer PII.
_PROBE_ALLOWLIST = frozenset(
    {
        "argus-probe",
        "argus",
        "probe",
        "test",
        "sample",
        "example.com",
        "user@example.com",
        "test@example.com",
    }
)

_MASK_CHARS_RE = re.compile(r"[\*●•#]{2,}|[xX]{4,}")
_KOREAN_MASKED_NAME_RE = re.compile(r"^[가-힣][\*●xX_·•]{1,}[가-힣]?$")
_PHONE_MASKED_RE = re.compile(r"^\d{2,3}[-\s]?[\*xX●•]{3,5}[-\s]?\d{4}$")

_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)^(.*(?:name|user|member|customer|insured|holder|email|mail|phone|mobile|tel|"
    r"rrn|jumin|resident|ssn|passport|account|acct|bank|card|credit|address|addr|birth|dob).*)$"
)

_BANK_NAMES = (
    "kb국민",
    "국민은행",
    "신한",
    "우리",
    "하나",
    "nh농협",
    "농협",
    "기업",
    "sc제일",
    "카카오뱅크",
    "케이뱅크",
    "토스뱅크",
    "부산은행",
    "대구은행",
    "경남은행",
)

_PATH_LEAK_RE = re.compile(
    r"(?i)(?:/etc/passwd|/var/www/|c:\\\\|\.env\b|/home/[\w.-]+/|"
    r"\.\./|\.\.\\|/wp-content/|/WEB-INF/)"
)

_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", _RE_FLAGS)
# Mobile: 010/011/016/017/018/019 — landline requires explicit separators (avoids ISO timestamp false positives).
_MOBILE_PHONE_RE = re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b")
_LANDLINE_PHONE_RE = re.compile(r"\b0\d{1,2}-\d{3,4}-\d{4}\b")
_ISO_DATETIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_SKIP_VALUE_FIELD_RE = re.compile(
    r"(?i)(?:^|\.)(?:timestamp|created_at|updated_at|modified_at|deleted_at|"
    r"createdat|updatedat|modifiedat|datetime|recorded_at|logged_at|"
    r"expires_at|expire_at|issued_at|last_login_at)(?:\.|$|\[)"
)
_RRN_RE = re.compile(r"\b(\d{6})[-\s]?([1-4]\d{6})\b")
_PASSPORT_RE = re.compile(r"\b[MmSsOo]\d{8,9}\b")
_CARD_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
_ACCOUNT_CTX_RE = re.compile(
    r"(?i)(account|acct|계좌|bank|은행|iban|deposit)"
)
_ACCOUNT_NUM_RE = re.compile(r"\b\d{10,16}\b")
# Korean personal names in API responses are usually 성(1) + 이름(2) = 3 hangul syllables.
# Product labels (스타리아, 쏘나타) fail the surname or length check.
_KOREAN_PERSON_NAME_3_RE = re.compile(r"^[가-힣]{3}$")
_KOREAN_SURNAMES = frozenset(
    "가 갈 감 강 검 경 계 고 공 곽 구 국 궁 궉 근 금 기 길 김 나 남 노 뇌 다 단 담 당 대 도 "
    "독 돈 동 두 라 란 랑 마 만 망 매 맹 명 모 무 문 묵 미 민 박 반 방 배 백 범 변 보 복 봉 부 "
    "비 빈 사 산 삼 상 서 석 선 설 섬 섭 성 소 손 송 수 순 승 시 신 심 아 안 애 양 어 엄 여 연 "
    "염 엽 영 예 오 옥 옹 완 왕 요 용 우 운 원 위 유 육 윤 은 음 이 인 임 장 저 전 정 제 조 종 "
    "좌 주 지 진 차 창 채 천 초 최 추 탁 탄 탕 판 팽 편 평 포 표 풍 피 필 하 학 한 함 해 허 현 "
    "형 호 홍 화 황 효 후 휴 흥 희".split()
)

# Product/catalog `name` paths — not personal names (cars[].name, modelName, …).
_CATALOG_ARRAY_PATH_RE = re.compile(
    r"(?i)\.(?:cars|products|items|goods|vehicles|rentals|rental_cars|"
    r"accommodations|rooms|flights|hotels|packages|skus|options|menus|"
    r"listings|catalog|inventory)\[\d+\]\.name$"
)
_PRODUCT_NAME_FIELD_RE = re.compile(
    r"(?i)^(?:model|product|brand|item|goods|vehicle|car|hotel|room|flight|airline|"
    r"category|manufacturer|maker|series|variant|trim|sku|campaign|banner|menu|"
    r"accommodation|rental|package|plan|option|title|subject|label)(?:name)?$"
)

_PERSON_NAME_FIELD_RE = re.compile(
    r"(?i)^(?:name|full_?name|user_?name|member_?name|customer_?name|"
    r"insured_?name|holder_?name|recipient_?name|real_?name|display_?name|"
    r"nick_?name|profile_?name|given_?name|family_?name|first_?name|last_?name|"
    r"sur_?name|owner_?name|guest_?name|passenger_?name|driver_?name|"
    r"patient_?name|employee_?name|staff_?name|author_?name|contact_?name|"
    r"applicant_?name|beneficiary_?name|depositor_?name|userName|memberName|"
    r"customerName|insuredName|realName|fullName|displayName|nickName)$"
)

_PERSON_NAME_HINT_RE = re.compile(
    r"(?i)(?:user|member|customer|insured|holder|recipient|guest|passenger|"
    r"driver|owner|patient|employee|staff|author|contact|profile|real|legal|"
    r"full|given|family|sur|first|last|nick|display|applicant|beneficiary|"
    r"claimant|depositor|withdrawer|sender|receiver|subscriber)"
)


@dataclass(frozen=True)
class PiiHit:
    rule_id: str
    category: str
    severity: str
    hint: str
    marker: str
    field_path: str | None = None
    sample: str | None = None


def _is_person_name_field(field_name: str | None, field_path: str | None) -> bool:
    """True for fields that typically hold a person's name, not product/catalog labels."""
    if not field_name:
        return False
    key = field_name.strip()
    lower = key.lower()
    path = field_path or ""

    if _PRODUCT_NAME_FIELD_RE.match(key):
        return False
    if lower == "name" and _CATALOG_ARRAY_PATH_RE.search(path):
        return False

    if _PERSON_NAME_FIELD_RE.match(key):
        return True
    return bool(_PERSON_NAME_HINT_RE.search(key))


def _looks_like_korean_person_name(value: str) -> bool:
    """Exactly 3 hangul syllables starting with a known Korean surname."""
    text = value.strip()
    if not _KOREAN_PERSON_NAME_3_RE.match(text):
        return False
    if is_masked_value(text):
        return False
    return text[0] in _KOREAN_SURNAMES


def _skip_field_for_pattern(field_path: str | None, rule_id: str) -> bool:
    if not field_path:
        return False
    if rule_id in ("phone_plain", "account_plain") and _SKIP_VALUE_FIELD_RE.search(field_path):
        return True
    return False


def _embedded_in_iso_datetime(match: str, text: str) -> bool:
    for dm in _ISO_DATETIME_RE.finditer(text):
        if match in dm.group(0):
            return True
    return bool(_ISO_DATETIME_RE.search(match))


def _iter_phone_matches(text: str) -> Iterator[re.Match[str]]:
    seen: set[str] = set()
    for pattern in (_MOBILE_PHONE_RE, _LANDLINE_PHONE_RE):
        for m in pattern.finditer(text):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            yield m


def _redact_sample(value: str, *, max_len: int = 48) -> str:
    text = value.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _is_probe_placeholder(value: str) -> bool:
    lower = value.strip().lower()
    if not lower:
        return True
    if lower in _PROBE_ALLOWLIST:
        return True
    if lower.startswith("argus") or lower.endswith("@example.com"):
        return True
    return False


def is_masked_value(value: str) -> bool:
    """Return True when the value appears intentionally masked."""
    text = value.strip()
    if not text or len(text) < 3:
        return True
    if _is_probe_placeholder(text):
        return True
    if _MASK_CHARS_RE.search(text):
        return True
    if _PHONE_MASKED_RE.match(text):
        return True
    if _KOREAN_MASKED_NAME_RE.match(text):
        return True
    # Partial redaction: keep last 4 digits only
    if re.match(r"^[\*xX●•#]{2,}\d{2,4}$", text):
        return True
    if re.match(r"^\d{2,4}[\*xX●•#]{2,}$", text):
        return True
    return False


def _valid_rrn_checksum(digits: str) -> bool:
    if len(digits) != 13 or not digits.isdigit():
        return False
    yy = int(digits[0:2])
    mm = int(digits[2:4])
    dd = int(digits[4:6])
    if mm < 1 or mm > 12 or dd < 1 or dd > 31:
        return False
    if yy > 99:
        return False
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    check = (11 - (total % 11)) % 10
    return check == int(digits[12])


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    parity = len(digits) % 2
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _hit_once(
    *,
    rule_id: str,
    category: str,
    severity: str,
    hint: str,
    value: str,
    field_path: str | None,
    seen: set[str],
) -> PiiHit | None:
    if _skip_field_for_pattern(field_path, rule_id):
        return None
    if is_masked_value(value):
        return None
    key = f"{rule_id}|{field_path or ''}|{value[:32]}"
    if key in seen:
        return None
    seen.add(key)
    return PiiHit(
        rule_id=rule_id,
        category=category,
        severity=severity,
        hint=hint,
        marker=_redact_sample(value),
        field_path=field_path,
        sample=_redact_sample(value, max_len=80),
    )


def _scan_text_blob(
    text: str,
    *,
    field_path: str | None,
    seen: set[str],
) -> list[PiiHit]:
    hits: list[PiiHit] = []
    if not text or not text.strip():
        return hits

    for m in _EMAIL_RE.finditer(text):
        h = _hit_once(
            rule_id="email_plain",
            category="email",
            severity="high",
            hint="Unmasked email address",
            value=m.group(0),
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    for m in _iter_phone_matches(text):
        token = m.group(0)
        if _embedded_in_iso_datetime(token, text):
            continue
        h = _hit_once(
            rule_id="phone_plain",
            category="phone",
            severity="high",
            hint="Unmasked phone number",
            value=token,
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    for m in _RRN_RE.finditer(text):
        digits = m.group(1) + m.group(2)
        if not _valid_rrn_checksum(digits):
            continue
        h = _hit_once(
            rule_id="rrn_plain",
            category="rrn",
            severity="high",
            hint="Unmasked resident registration number (주민등록번호)",
            value=m.group(0),
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    for m in _PASSPORT_RE.finditer(text):
        h = _hit_once(
            rule_id="passport_plain",
            category="passport",
            severity="high",
            hint="Unmasked passport number",
            value=m.group(0),
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if not _luhn_ok(digits):
            continue
        h = _hit_once(
            rule_id="card_plain",
            category="payment",
            severity="high",
            hint="Unmasked payment card number",
            value=m.group(0),
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    lower = text.lower()
    if _ACCOUNT_CTX_RE.search(text) or any(bank in lower for bank in _BANK_NAMES):
        for m in _ACCOUNT_NUM_RE.finditer(text):
            if _embedded_in_iso_datetime(m.group(0), text):
                continue
            h = _hit_once(
                rule_id="account_plain",
                category="account",
                severity="high",
                hint="Unmasked bank/account number near banking context",
                value=m.group(0),
                field_path=field_path,
                seen=seen,
            )
            if h:
                hits.append(h)

    if _PATH_LEAK_RE.search(text):
        m = _PATH_LEAK_RE.search(text)
        frag = m.group(0) if m else text[:60]
        h = _hit_once(
            rule_id="path_structure",
            category="path",
            severity="medium",
            hint="Directory or file structure in parameter/value",
            value=frag,
            field_path=field_path,
            seen=seen,
        )
        if h:
            hits.append(h)

    return hits


def _walk_json(
    node: Any,
    path: str,
    seen: set[str],
) -> list[PiiHit]:
    hits: list[PiiHit] = []
    if isinstance(node, dict):
        for key, val in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            if isinstance(val, str):
                hits.extend(_scan_string_value(val, field_path=child_path, field_name=str(key), seen=seen))
            else:
                hits.extend(_walk_json(val, child_path, seen))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            hits.extend(_walk_json(item, f"{path}[{i}]", seen))
    elif isinstance(node, str):
        hits.extend(_scan_string_value(node, field_path=path or "value", field_name=None, seen=seen))
    return hits


def _scan_string_value(
    value: str,
    *,
    field_path: str | None,
    field_name: str | None,
    seen: set[str],
) -> list[PiiHit]:
    hits = _scan_text_blob(value, field_path=field_path, seen=seen)
    if field_name and _is_person_name_field(field_name, field_path):
        if _looks_like_korean_person_name(value):
            h = _hit_once(
                rule_id="korean_name_plain",
                category="name",
                severity="medium",
                hint="Unmasked Korean personal name (3 chars, known surname) in sensitive field",
                value=value.strip(),
                field_path=field_path,
                seen=seen,
            )
            if h:
                hits.append(h)
    if field_name and _SENSITIVE_FIELD_RE.match(field_name):
        name_key = field_name.lower()
        if any(k in name_key for k in ("bank", "은행")) and len(value.strip()) >= 2:
            lower = value.lower()
            if any(b in lower for b in _BANK_NAMES) and not is_masked_value(value):
                h = _hit_once(
                    rule_id="bank_name_plain",
                    category="bank",
                    severity="medium",
                    hint="Bank name exposed in clear text",
                    value=value.strip(),
                    field_path=field_path,
                    seen=seen,
                )
                if h:
                    hits.append(h)
    return hits


def analyze_text(
    text: str | bytes | None,
    *,
    field_path: str | None = None,
) -> list[PiiHit]:
    seen: set[str] = set()
    if text is None:
        return []
    if isinstance(text, bytes):
        blob = text.decode("utf-8", errors="replace")
    else:
        blob = text
    if len(blob) > 500_000:
        blob = blob[:500_000]
    blob = blob.strip()
    if not blob:
        return []

    try:
        parsed = json.loads(blob)
        return _walk_json(parsed, field_path or "body", seen)
    except (json.JSONDecodeError, TypeError):
        return _scan_text_blob(blob, field_path=field_path, seen=seen)


def analyze_url_params(url: str) -> list[PiiHit]:
    seen: set[str] = set()
    hits: list[PiiHit] = []
    parsed = urlparse(url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        path = f"query:{key}"
        hits.extend(_scan_string_value(value, field_path=path, field_name=key, seen=seen))
    if parsed.path:
        for seg in parsed.path.split("/"):
            if not seg or seg.isdigit():
                continue
            hits.extend(_scan_string_value(seg, field_path=f"path:{seg}", field_name=None, seen=seen))
    return hits


def analyze_http_plain(
  url: str,
  *,
  has_sensitive: bool,
) -> PiiHit | None:
    if not has_sensitive:
        return None
    if url.lower().startswith("https://"):
        return None
    if not url.lower().startswith("http://"):
        return None
    return PiiHit(
        rule_id="http_plain_sensitive",
        category="transport",
        severity="high",
        hint="Sensitive data sent over unencrypted HTTP",
        marker=urlparse(url).netloc or url[:60],
        field_path="transport",
    )


def remediation_hint(rule_id: str) -> str:
    hints = {
        "email_plain": "Mask emails in API responses/URLs or use opaque tokens.",
        "phone_plain": "Mask phone numbers (e.g. 010-****-1234) or encrypt at rest/in transit.",
        "rrn_plain": "Never expose full RRN; use masked or tokenized identifiers.",
        "passport_plain": "Mask passport numbers; store encrypted server-side only.",
        "card_plain": "Never return full PAN; use PCI-compliant tokenization.",
        "account_plain": "Mask account numbers; avoid placing them in URL query strings.",
        "korean_name_plain": "Mask personal names in responses (e.g. 홍*동).",
        "bank_name_plain": "Avoid exposing full banking details in client-visible fields.",
        "path_structure": "Do not put file paths or internal directories in parameters.",
        "http_plain_sensitive": "Use HTTPS (TLS) for any endpoint carrying personal data.",
    }
    return hints.get(rule_id, "Mask or tokenize sensitive values; avoid exposing them in requests/responses.")


def audit_sensitive_values(
    text: str | bytes | None,
) -> dict[str, int]:
    """Count sensitive-field values seen (masked or unmasked) for scan coverage stats."""
    counts = {
        "sensitive_fields": 0,
        "unmasked_values": 0,
        "masked_values": 0,
        "emails_seen": 0,
        "phones_seen": 0,
    }
    if text is None:
        return counts
    blob = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    blob = blob.strip()
    if not blob:
        return counts
    try:
        parsed = json.loads(blob)
    except (json.JSONDecodeError, TypeError):
        return counts

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                child = f"{path}.{key}" if path else str(key)
                if isinstance(val, str) and _SENSITIVE_FIELD_RE.match(str(key)):
                    counts["sensitive_fields"] += 1
                    name_key = str(key).lower()
                    if "email" in name_key or "mail" in name_key:
                        if "@" in val:
                            counts["emails_seen"] += 1
                    if any(k in name_key for k in ("phone", "mobile", "tel")):
                        if any(c.isdigit() for c in val):
                            counts["phones_seen"] += 1
                    if is_masked_value(val):
                        counts["masked_values"] += 1
                    else:
                        counts["unmasked_values"] += 1
                elif isinstance(val, (dict, list)):
                    _walk(val, child)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, f"{path}[{i}]")

    _walk(parsed, "body")
    return counts
