# ARGUS 진단 모듈 가이드 — 2026-07-01 구현분

KISA Web/API 개발보안 가이드라인 중 **`DIAGNOSIS_MODULES.md`에 없는 9개 모듈**을 2026-07-01에 구현·연동한 내용을 정리한 문서입니다.

> **이 문서 범위:** 1-5 · 3-2 · 3-4 · 3-5 · 3-6 · 4-1 · 4-2 · 5-2 · 6-1  
> **별도 문서:** 2-2 · 6-2 · 7-1 ~ 7-4 → [`DIAGNOSIS_MODULES.md`](./DIAGNOSIS_MODULES.md)

---

## 1. 개요

| ID | 제목 | 장 | 엔진 | 핵심 질문 |
|----|------|-----|------|-----------|
| **1-5** | 검증되지 않은 리다이렉트와 포워드 | 1 | `httpx+zap` | 외부 URL로 열리는 redirect·CORS·crossdomain이 있는가? |
| **3-2** | 인증 실패 횟수 제한 | 3 | `httpx` | 연속 로그인 실패 시 잠금·rate limit이 있는가? |
| **3-4** | 관리자 페이지 분리 여부 | 3 | `httpx`* | admin·user가 호스트/로그인/경로에서 분리돼 있는가? |
| **3-5** | 검색엔진 정보 노출 가능성 | 3 | `httpx` | robots.txt·noindex/nofollow 현황은? (인벤토리) |
| **3-6** | 백업·테스트 파일 존재 여부 | 3 | `httpx` | `.bak`·`.env`·debug 파일이 GET으로 열리는가? |
| **4-1** | 쿠키·웹 스토리지 조작 가능성 | 4 | `httpx` | 쿠키 보안 속성·타 계정 쿠키·토큰 변조가 통하는가? |
| **4-2** | 인증(세션·토큰) 값 안전성 | 4 | `httpx` | JWT/토큰 강도·재로그인·중복 로그인·로그아웃 무효화는? |
| **5-2** | 요청/응답 주요정보 포함 여부 | 5 | `httpx` | 이메일·전화·실명 등 PII가 마스킹 없이 노출되는가? |
| **6-1** | 오류페이지 정보 노출 | 6 | `httpx+zap` | fuzz 시 stack trace·SQL·내부 경로가 새는가? |

\*3-4는 manifest `engine: httpx`이나 **실제 HTTP 프로브 없음** — api-tree·verify-report 정적 분석.

**공통 철학 (이번 9개도 동일)**

- **httpx = 본진**: ARGUS 자체 판정·증거·재현
- **ZAP = 보조** (1-5, 6-1): optional supplemental
- **인벤토리 기반**: `api-tree` + Dashboard Base URLs + Test Accounts
- **결과**: `reports/latest.yaml` + Dashboard Diagnosis 페이지

---

## 2. 공통 아키텍처 (이번에 추가·정비)

### 2.1 모듈 등록·실행

`DIAGNOSIS_MODULES.md` §2.1과 동일 패턴. 각 모듈:

```
backend/diagnosis/modules/{id}/
  manifest.yaml
  module.py          # G{xx}Module
  scanner.py
  probes.py / *_rules.py / targets.py
  reports/latest.yaml
```

`diagnosis_service.run_section()` → `dp.reset()` → `mod.run(ctx)` → `dp.finish()`.

### 2.2 진행률 UI (Progress) — **이번에 전 모듈 확장**

| 파일 | 역할 |
|------|------|
| `backend/app/services/diagnosis_progress.py` | in-memory 상태, `GET /api/diagnosis/progress` |
| `backend/diagnosis/progress_reporter.py` | `prepare`, `phase`, `endpoint_progress`, `step_progress`, `zap_phase` |
| `frontend/src/components/DiagnosisPage.tsx` | 실행 중 progress 폴링·모듈별 stats 줄 |

| 모듈 | Progress 방식 |
|------|----------------|
| 1-5, 3-2, 3-4, 3-5, 3-6, 4-1, 4-2 | `progress_reporter` |
| 5-2, 6-1 | `diagnosis_progress.update` 직접 (`httpx_pii` / `httpx_fuzz` phase) |

### 2.3 Probe URL (`localhost` vs Docker)

**문제:** Docker 컨테이너 안에서 `localhost:8080` → 컨테이너 자신 → 전 요청 실패.

| 환경 | 동작 |
|------|------|
| 호스트에서 backend 직접 실행 | `localhost` **유지** |
| Docker Compose | `ARGUS_PROBE_HOST=host.docker.internal` 일 때만 rewrite |

| 파일 |
|------|
| `backend/app/services/zap_util.py` — `probe_url()` |
| `backend/app/services/verify_service.py` |
| `backend/diagnosis/modules/{1-5,3-5,3-6,5-2}/targets.py` — `probe_base_url()` |
| `docker-compose.yml` |

Dashboard·리포트 표시 URL은 `localhost`, 실제 HTTP만 호스트로 전달.

### 2.4 API run body 키

| 모듈 | POST body 키 | config.yaml 키 |
|------|-------------|----------------|
| 1-5 | `g15` | `diagnosis_1_5` |
| 3-2 | `g32` | `diagnosis_3_2` |
| 3-4 | *(없음 — 원클릭)* | — |
| 3-5 | `g35` | `diagnosis_3_5` |
| 3-6 | `g36` | `diagnosis_3_6` |
| 4-1 | `g41` | `diagnosis_4_1` |
| 4-2 | *(없음 — config만)* | `diagnosis_4_2` |
| 5-2 | `g52` | `diagnosis_5_2` |
| 6-1 | `g61` | `diagnosis_6_1` |

### 2.5 프론트엔드 패턴

| 모듈 | Options TS | Start Dialog | Options Panel | Stats 줄 |
|------|-----------|--------------|---------------|----------|
| 1-5 | `g15DiagnosisOptions.ts` | G15 | G15 | `isG15Stats` |
| 3-2 | `g32DiagnosisOptions.ts` | G32 | G32 | `isG32Stats` |
| 3-4 | — | — | — | `isG34Stats` |
| 3-5 | `g35DiagnosisOptions.ts` | G35 | G35 | `isG35Stats` |
| 3-6 | `g36DiagnosisOptions.ts` | G36 | G36 | `isG36Stats` |
| 4-1 | `g41DiagnosisOptions.ts` | G41 | G41 | `isG41Stats` |
| 4-2 | — | — | — | `isG42Stats` |
| 5-2 | `g52DiagnosisOptions.ts` | G52 | G52 | `isG52Stats` |
| 6-1 | `g61DiagnosisOptions.ts` | G61 | G61 | `isG61Stats` |

5-2·6-1은 smoke / exhaustive / custom 프리셋 탭 제공.

---

## 3. 모듈별 상세

### 3.1 1-5 — 검증되지 않은 리다이렉트와 포워드

**목표:** Open Redirect, CORS misconfig, `crossdomain.xml` 노출.

**파이프라인**

```
Base URL + api-tree
  → Phase A: redirect-like query param → 외부 sink URL
  → CORS probe (Origin 변조)
  → crossdomain.xml GET
  → (optional) ZAP Rule 40031 / 10028
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | redirect job 생성, CORS/crossdomain 대상, `probe_base_url` |
| `probes.py` | httpx 실행 |
| `redirect_rules.py` | open redirect·CORS·crossdomain 판정 |
| `zap_scan.py` | ZAP supplemental |

**Dashboard 옵션 (`g15`)**

- `probe_mode`: `base_only` | `sample` | `full`
- `cors_enabled`, `crossdomain_enabled`
- `redirect_sink_base`, `redirect_sink_port`, `cors_probe_origin`
- `zap_enabled`, `zap_max_minutes`
- `max_phase_a_jobs`, `max_phase_b_jobs`, `timeout`

Env: `ARGUS_REDIRECT_SINK_BASE`, `ARGUS_REDIRECT_SINK_PORT`, `ARGUS_PROBE_HOST`

**테스트:** `tests/test_g15_redirect.py`

---

### 3.2 3-2 — 인증 실패 횟수 제한

**목표:** 동일 계정 **연속 틀린 비밀번호** N회 시 잠금·rate limit 유무.  
(6-2는 A/B/C 응답 **동일성** — 다른 항목.)

**파이프라인**

```
login_discovery → login URL 목록
  → URL별 test account 매칭
  → wrong password × max_attempts (기본 12)
  → lockout_rules: 429/403/423, Retry-After, 메시지 변화
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `probes.py` | 연속 실패 로그인 (`probe_url`) |
| `lockout_rules.py` | 잠금·rate limit 판정 |
| `SCOPE.md` | 스코프 문서 |

**Dashboard 옵션 (`g32`)**

- `max_attempts` (3–25), `timeout`, `interval_sec`
- `wrong_password` (기본 `__ARGUS_INVALID_PASSWORD__`)
- `probe_account_email`, `strict`

**주의:** Test Account가 잠길 수 있음 — 전용 계정 권장.

**테스트:** `tests/test_g32_lockout.py`

---

### 3.3 3-4 — 관리자 페이지 분리 여부

**목표:** admin·user **표면 분리** 여부 (호스트, 서브도메인, 로그인 URL, 추측 가능 경로).

**파이프라인 (HTTP 없음)**

```
api-tree + verify-report.json + dashboard base URLs
  → separation_rules.py
  → info/warn finding (동일 호스트·동일 login·guessable /admin 등)
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | inventory 로드, extra admin hosts |
| `separation_rules.py` | 분리 휴리스틱 |

**UI:** 옵션 다이얼로그 없음 — 카드에서 원클릭 Run.  
finding은 `inventory` / `info` 섹션 기본 펼침.

**테스트:** `tests/test_g34_separation.py`

---

### 3.4 3-5 — 검색엔진 정보 노출 가능성

**목표:** robots.txt·`noindex`/`nofollow` **인벤토리** (v1은 fail/warn 없음).

**파이프라인**

```
anonymous pass: frontend base /robots.txt + 페이지 GET
authenticated pass: test account 세션별 동일 URL 재-probe
  → robots_rules: Disallow/Allow, HTML meta robots
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | frontend/API base dedupe, `probe_base_url` |
| `probes.py` | `run_robots_inventory`, `run_page_inventory` |
| `robots_rules.py` | 파싱·meta 추출 |
| `SCOPE.md` | SPA 한계·base 선별 규칙 |

**Dashboard 옵션 (`g35`)**

- `probe_mode`: `base_only` | `sample` | `full`
- `sample_size`, `timeout`, `extra_probe_paths`

**테스트:** `tests/test_g35_robots.py`

---

### 3.5 3-6 — 백업·테스트 파일 존재 여부

**목표:** wordlist 경로 GET — `.bak`, `.env`, `web.config`, debug 파일 노출.

**파이프라인**

```
wordlist (assets/backup-test-files.txt) × base URLs
  → anonymous pass (KISA fail 기준)
  → authenticated pass (세션별 비교)
  → file_rules: 확장자·본문 휴리스틱
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | wordlist + api-tree path, `probe_base_url` |
| `probes.py` | `run_file_probes` |
| `file_rules.py` | backup/test/debug 분류 |
| `SCOPE.md` | 스코프 |

**Dashboard 옵션 (`g36`)**

- `probe_mode` (기본 `base_only`), `sample_size`, `timeout`
- `extra_probe_paths`

**테스트:** `tests/test_g36_files.py`

---

### 3.6 4-1 — 쿠키·웹 스토리지 조작 가능성

**목표:** (1) 로그인 응답 쿠키 속성 (2) 타 계정 쿠키 재사용 (3) Bearer/Cookie 변조.

**파이프라인**

```
Phase A — cookie_attr: login 응답 Set-Cookie → HttpOnly/Secure/SameSite
Phase B — cross_cookie: 계정 A 쿠키로 계정 B API 호출
Phase C — tamper: Authorization/Cookie 변조 (auth_profiles)
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | auth-required endpoint 샘플링 |
| `probes.py` | cross/tamper httpx (`probe_url`) |
| `cookie_rules.py` | cross leak·tamper 판정 |
| `cookie_attr_probes.py` | 정적 쿠키 속성 분석 |

**Dashboard 옵션 (`g41`)**

- `probe_mode`, `sample_size`, `max_endpoints`, `max_pairs_per_endpoint`
- `cross_cookie_enabled`, `tamper_enabled`, `cookie_attr_enabled`, `cookie_attr_strict`
- `auth_required_only`, `auth_profiles`, `partial_cross_tamper`

**테스트:** `tests/test_g41_cookie.py`, `tests/test_g41_cookie_attr.py`

---

### 3.7 4-2 — 인증(세션·토큰) 값 안전성

**목표:** 토큰 정적 분석 + 라이프사이클 실probe.

**파이프라인**

```
Test Accounts 로그인 → 세션 수집
  → token_analyzer: JWT alg/exp/entropy, opaque 길이·엔트로피
  → lifecycle_probes:
      - 재로그인 시 토큰 변경 여부
      - 동시 로그인 (duplicate session)
      - cross-IP duplicate login
      - 서버/클라이언트 logout 후 토큰 무효화
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `token_analyzer.py` | JWT·opaque 정적 분석 |
| `lifecycle_probes.py` | relogin·logout probe (`probe_url`) |
| `targets.py` | logout URL, probe account |

**Dashboard:** 옵션 UI 없음 — `config.yaml` `diagnosis_4_2`만.

**주요 config**

- `max_token_lifetime_minutes`, `min_token_length`, `min_entropy`
- `relogin_enabled`, `duplicate_login_enabled`, `duplicate_login_ip_enabled`
- `logout_enabled`, `client_logout_enabled`, `refresh_path`
- `probe_account_email`, `timeout`

**버그 수정 (7/1):** progress `lifecycle_steps` 계산 시 `pick_probe_account()` **이전**에 `account` 참조 → `UnboundLocalError` 500. 계정 해석을 앞으로 이동.

**테스트:** `tests/test_g42_token.py`

---

### 3.8 5-2 — 요청/응답 주요정보 포함 여부

**목표:** 요청 URL·body, 응답 body에 **마스킹 없는 PII**.

**파이프라인**

```
api-tree endpoint dedupe (8080/8081 > 5173)
  → × 6 auth pass (anonymous + test accounts 5)
  → analyze_url_params / analyze_text (JSON walk)
  → collapse_findings (동일 hit auth 묶기)
```

**탐지 규칙 (`pii_rules.py`)**

| rule_id | 내용 |
|---------|------|
| `email_plain` | 이메일 |
| `phone_plain` | 휴대/유선 (ISO timestamp 오탐 제외) |
| `rrn_plain` | 주민번호 (체크섬) |
| `passport_plain`, `card_plain`, `account_plain` | 여권·카드·계좌 |
| `korean_name_plain` | 이름 필드 + **성씨 + 3글자 한글** |
| `bank_name_plain` | 은행명 필드 |
| `http_plain_sensitive` | HTTP 전송 (다른 PII 있을 때만) |
| `path_structure` | 내부 경로 노출 |

**한국어 이름 규칙 (최종)**

- 사람 이름 필드만 (`name`, `nickname`, `insuredName` …)
- 상품 필드 제외 (`modelName`, `cars[].name` …)
- 값: `^[가-힣]{3}$` + 첫 글자 ∈ `_KOREAN_SURNAMES` (~150개)
- `온데카`·`예린`·`에어루나` 등 브랜드/닉네임 → **미탐 (의도)**  
  onde-pilot에서 `korean_name_plain` 0건 + email/phone 다수 = 정상.

**주요 파일**

| 파일 | 역할 |
|------|------|
| `targets.py` | endpoint 수집, dedupe, `probe_base_url` |
| `probes.py` | multi-auth probe, coverage stats |
| `pii_rules.py` | PII 판정 |
| `scanner.py` | 오케스트레이션, stats finding |

**Dashboard 옵션 (`g52`)**

- `probe_mode`: `sample` | `full`
- `check_request_url` / `check_request_body` / `check_response_body`
- `check_http_plain`, `enable_auth_modes`
- `sample_size`, `max_endpoints`, `timeout`

**onde-pilot full 실행 예**

```
250 endpoints × 6 auth · 25 PII (email 14, phone 7, transport 4)
1491 bodies / 176 OK
```

**테스트:** `tests/test_g52_pii.py`

---

### 3.9 6-1 — 오류페이지 정보 노출

**목표:** API fuzz로 에러 유발 → stack trace·SQL·내부 경로 유출.

**파이프라인**

```
api-tree endpoint 샘플
  → triggers + payloads (param/body/path/method/header)
  → error_rules: Java stack, SQL syntax, /var/www 등
  → (optional) ZAP unified fuzz + Rule 90022/10023
  → collapse_findings
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `payloads.py` | malformed·long·type confusion payload |
| `triggers.py` | endpoint별 trigger 선택 |
| `probes.py` | request budget, httpx fuzz |
| `error_rules.py` | disclosure 패턴 |
| `zap_scan.py` | ZAP phase (`probe_url`) |

**Dashboard 옵션 (`g61`)**

- `probe_mode`, `sample_size`, `max_endpoints`, `max_requests`
- `enable_param_fuzz`, `enable_body_fuzz`, `enable_path_fuzz`, `enable_method_fuzz`, `enable_header_fuzz`
- `httpx_enabled`, `zap_enabled`, `zap_unified_enabled`, `zap_supplemental_enabled`
- `enable_auth_modes`, smoke/exhaustive 프리셋

**테스트:** `tests/test_g61_error.py`, `tests/test_g61_zap.py`

---

## 4. 모듈 간 관계

| 주제 | 주 모듈 | 연관 |
|------|---------|------|
| 로그인 실패 응답 동일성 | **6-2** | 3-2와 구분 |
| 로그인 실패 **횟수** 제한 | **3-2** | test account 잠금 주의 |
| 계정 존재 여부 (enumeration) | **6-2** | 3-3(미구현)과 연관 |
| admin 분리 | **3-4** | 4-4(미구현)과 연관 |
| 쿠키 조작 | **4-1** | 4-2 토큰·세션과 연계 |
| PII in response | **5-2** | 5-1 소스코드(미구현)와 분리 |
| Error body leak | **6-1** | 6-2 failure uniformity와 분리 |
| Open redirect | **1-5** | 1-3 hidden field(미구현)와 분리 |
| Hidden/backup file | **3-6** | 2-2 forced browse와 wordlist 공유 가능 |
| Directory listing | **7-2** | `DIAGNOSIS_MODULES.md` |

---

## 5. 사전 준비

`DIAGNOSIS_MODULES.md` §5와 동일 + 아래 모듈별:

| 모듈 | 추가 요구 |
|------|-----------|
| 3-2, 4-2, 5-2, 6-1 | Test Accounts + login discovery |
| 3-4 | verify-report (Build/Verify 후) |
| 3-5 | frontend base (5173) + authenticated pass용 login |
| 1-5 | redirect sink URL (env 또는 옵션) |
| 6-1, 1-5 | ZAP optional — `docker compose` |

---

## 6. 실행

### Dashboard

Diagnosis 페이지 → 해당 카드 → Run (옵션 있는 모듈은 다이얼로그)

### API 예시

```http
POST /api/diagnosis/modules/5-2/run
Content-Type: application/json

{
  "g52": {
    "probe_mode": "full",
    "check_response_body": true,
    "enable_auth_modes": true
  }
}
```

### config.yaml 예시

```yaml
diagnosis_3_2:
  max_attempts: 12
  strict: true

diagnosis_4_2:
  relogin_enabled: true
  duplicate_login_enabled: true
  logout_enabled: true

diagnosis_5_2:
  probe_mode: sample
  sample_size: 40

diagnosis_6_1:
  probe_mode: sample
  zap_enabled: true
  max_requests: 500
```

---

## 7. 테스트

```powershell
cd backend

# 이번 9개 모듈
python -m pytest tests/test_g15_redirect.py -q
python -m pytest tests/test_g32_lockout.py -q
python -m pytest tests/test_g34_separation.py -q
python -m pytest tests/test_g35_robots.py -q
python -m pytest tests/test_g36_files.py -q
python -m pytest tests/test_g41_cookie.py tests/test_g41_cookie_attr.py -q
python -m pytest tests/test_g42_token.py -q
python -m pytest tests/test_g52_pii.py -q
python -m pytest tests/test_g61_error.py tests/test_g61_zap.py -q

# 공통
python -m pytest tests/test_diagnosis.py -q
```

---

## 8. 디렉터리 빠른 참조

```
ARGUS_1/
  DIAGNOSIS_MODULES.md              ← 2-2, 6-2, 7-1~7-4
  DIAGNOSIS_WORKLOG_2026-07-01.md   ← 이 문서 (9개 모듈)
  backend/diagnosis/
    progress_reporter.py
    probe_auth.py
    modules/
      1-5/   … redirect, CORS
      3-2/   … lockout
      3-4/   … admin separation (static)
      3-5/   … robots / noindex inventory
      3-6/   … backup files
      4-1/   … cookie cross/tamper
      4-2/   … token lifecycle
      5-2/   … PII
      6-1/   … error disclosure fuzz
  backend/app/services/
    diagnosis_progress.py
    diagnosis_service.py
    zap_util.py
  frontend/src/
    components/DiagnosisPage.tsx
    lib/g{15,32,35,36,41,52,61}DiagnosisOptions.ts
    components/G{15,32,35,36,41,52,61}Diagnosis*.tsx
  backend/tests/
    test_g15_*.py … test_g61_*.py
```

모듈별 세부 제외·판정 기준은 `backend/diagnosis/modules/{id}/SCOPE.md` (3-2, 3-5, 3-6 등) 참고.
