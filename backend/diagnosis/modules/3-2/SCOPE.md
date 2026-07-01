# 3-2 인증 실패 횟수 제한

KISA Web/API Guideline **3-2**.  
동일 계정으로 **연속 로그인 실패** 시 계정 잠금·rate limit·응답 변경 등 **제한**이 있는지 점검.

6-2(실패 응답 **동일성**)와 다름 — 3-2는 **같은 이메일 + 틀린 비밀번호 N회** 반복.

## httpx lockout probe

| 항목 | 내용 |
|------|------|
| 대상 | inventory + dashboard에서 수집된 **login URL** (user · admin 등) |
| 계정 | Test Accounts — URL별 자동 선택 (admin URL → admin 이메일 우선) |
| 비밀번호 | **틀린 비밀번호만** 사용 (기본 `__ARGUS_INVALID_PASSWORD__`) |
| 시도 | `max_attempts` (기본 12, 최대 25) |
| 판정 | N회 내 429/403/423, Retry-After, 메시지·코드 변경 → **pass (info)** / 변화 없음 → **fail (medium)** |

## 주의

- **Test Account가 잠길 수 있음** — 3-2 전용 계정 권장
- 올바른 비밀번호는 사용하지 않음 (연속 실패만)
- IP rate limit vs 계정 lockout은 finding `limit_type`으로 구분

## 설정 (`diagnosis_3_2`)

- `max_attempts`, `timeout`, `interval_sec`, `wrong_password`, `probe_account_email`, `strict`
