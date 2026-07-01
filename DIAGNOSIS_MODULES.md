# ARGUS 진단 모듈 가이드 (2-2 · 6-2 · 7-1 ~ 7-4)

KISA Web/API 개발보안 가이드라인 중 **현재 구현 완료된 6개 진단 모듈**의 설계·구현·실행 방법을 정리한 문서입니다.

---

## 1. 개요

| ID | 제목 | 장 | 엔진 | 핵심 질문 |
|----|------|-----|------|-----------|
| **2-2** | 중요 정보 파일 다운로드 가능성 | 2 | `httpx+zap` | Path Traversal·숨은 파일·무인증 다운로드가 가능한가? |
| **6-2** | 일괄적인 오류 처리 페이지 존재 여부 | 6 | `httpx+zap` | 로그인 실패 시 계정 존재 여부가 응답으로 드러나는가? |
| **7-1** | Client Request Method | 7 | `httpx+zap` | TRACE 등 위험 HTTP 메서드가 허용되는가? |
| **7-2** | 파일 목록화 가능성 | 7 | `httpx+zap` | 디렉터리 listing이 노출되는가? |
| **7-3** | 서버 헤더정보 노출 | 7 | `httpx+zap` | `Server`, `X-Powered-By` 등 스택 정보가 노출되는가? |
| **7-4** | 취약한 보안설정 | 7 | `httpx+zap` | HSTS·CSP·Cookie Secure 등 보안 헤더가 빠졌는가? |

**공통 철학**

- **httpx = 본진**: ARGUS 자체 판정 로직으로 빠르고 재현 가능한 프로브
- **ZAP = 보조**: Active/Passive scanner rule로 교차 검증 (옵션, Docker Compose에 ZAP 포함)
- **인벤토리 기반**: `api-tree` + Dashboard Base URLs에서 대상 자동 수집
- **결과 저장**: 각 모듈 `reports/latest.yaml` + Dashboard Diagnosis 페이지

---

## 2. 공통 아키텍처

### 2.1 모듈 등록·실행 흐름

```
Dashboard (DiagnosisPage)
    → POST /api/diagnosis/modules/{section_id}/run  (+ g22/g62/g71… 옵션 body)
        → diagnosis_service.run_section()
            → DiagnosisContext (config.yaml + data/ + run overrides)
            → GxxModule.run(ctx)
                → scanner.run_gxx_scan()
                → SectionReport + stats finding
                → reports/latest.yaml 저장
```

**핵심 파일**

| 역할 | 경로 |
|------|------|
| 모듈 베이스 | `backend/diagnosis/base.py` |
| 레지스트리 | `backend/diagnosis/registry.py` |
| API 라우터 | `backend/app/routers/diagnosis.py` |
| 서비스 | `backend/app/services/diagnosis_service.py` |
| Finding 모델 | `backend/diagnosis/result.py` |

각 구현 모듈은 동일한 패턴을 따릅니다.

```
backend/diagnosis/modules/{section-id}/
  manifest.yaml      # id, title, chapter, implemented, engine
  module.py          # GxxModule extends DiagnosisModule
  scanner.py         # 오케스트레이션 (옵션 파싱 → httpx → ZAP → status)
  probes.py          # httpx 프로브 실행
  *_rules.py         # 판정·비교 로직 (모듈별)
  targets.py         # probe URL 수집 (7-x 공통 패턴)
  zap_scan.py        # ZAP phase (해당 모듈)
  SCOPE.md           # 모듈별 상세 스코프
  assets/            # wordlist, payload (2-2, 7-2)
  reports/latest.yaml
```

`module.py`는 `importlib`로 `scanner.py`를 동적 로드하고, 스캔 후 **stats finding**을 findings 맨 앞에 삽입합니다. UI는 `"2-2 scan statistics"` 등 stats 메시지를 필터링해 상단 요약줄에만 표시합니다.

### 2.2 httpx + ZAP 이중 엔진

| 패턴 | 모듈 | httpx | ZAP |
|------|------|-------|-----|
| Unified 판정 | 2-2 | traversal·forced browse·unauth download | 동일 로직 + native rule (0, 6, 40035…) |
| httpx 우선 + ZAP 보조 | 6-2 | A/B/C 로그인 POST | Active **40023** (Username Enumeration) |
| httpx + optional active | 7-1, 7-2 | 메서드/디렉터리 프로브 | Active **90028** / **0** |
| httpx + optional passive | 7-3, 7-4 | 헤더·보안설정 규칙 | Passive **10036**, **10035** 등 |

ZAP 공통 유틸: `backend/app/services/zap_util.py`

- `connect_zap`, `ensure_zap_proxy`, `probe_url` (Docker 내부 `host.docker.internal` 치환)
- `reset_zap_workspace` — run 전후 `newSession` + alert 삭제 (2-2/7-x run 간 alert 섞임 방지)

ZAP 미기동·add-on 없음 → `ZapNotAvailableError` → httpx 결과만 반환, stats에 `zap.error` 기록.

### 2.3 Probe target 수집 (7-1 ~ 7-4 공통)

`targets.py` + `probe_mode`:

| 모드 | 동작 |
|------|------|
| `base_only` | Dashboard Base URLs × `/` (+ extra paths) |
| `sample` | 위 + api-tree에서 base당 N개 path |
| `full` | api-tree 매칭 path 전수 |

Base URL 출처: `load_dashboard_base_urls()` → `data/base-urls.json`  
api-tree: `data/api-tree-verified.json` → `api-tree-ready.json` → `api-tree.json` 순 fallback.

### 2.4 Finding · Pass/Fail

- `DiagnosisFinding`: `severity`, `message`, `evidence` (rule_id, engine, url, 비교 결과 등)
- `SectionReport.status`: `pass` | `fail` | `error` | `skipped`
- UI (`DiagnosisPage.tsx`): httpx / ZAP / info 섹션으로 그룹핑

---

## 3. 모듈별 상세

### 3.1 2-2 — 중요 정보 파일 다운로드 가능성

**목표:** Path Traversal, 필터 우회, 숨은 민감 파일, 무인증 다운로드를 탐지.

**파이프라인** (`scanner.py` → `run_g22_scan`)

```
1. api-tree 로드
2. candidates.py — 2-2 점수·태그로 후보 endpoint 선별 (또는 scan_all_inventory)
3. design_review.py — path=/filename= 직접 파라미터 → info finding
4. httpx phase (runner.py)
   - unauth download probe
   - traversal fuzz (assets/path-traversal-payloads.txt)
   - forced browse (assets/forced-browse-download.txt)
   - response_analysis.compare_to_baseline — PDF LFI 등 앱 특화 판정
5. ZAP phase (zap_scan.py, optional)
   - Rule 6, 0, 40035, 40034, 40032, 40008
   - hybrid: ZAP sendRequest + ARGUS compare_to_baseline
6. ReplaySession — evidence/replay/ HTML 패널 저장
```

**주요 파일**

| 파일 | 역할 |
|------|------|
| `candidates.py` | export/report/download 태그·path 휴리스틱 |
| `runner.py` | httpx 프로브 오케스트레이션 |
| `traversal_fuzz.py` | path traversal payload 주입 |
| `auth_access.py` | 인증/무인증 비교 (v2 예정) |
| `transport.py` | httpx 클라이언트 래퍼 |
| `response_analysis.py` | baseline 대비 응답·PDF 분석 |

**Dashboard 옵션** (`g22DiagnosisOptions.ts`)

- httpx on/off, ZAP on/off
- `scanAllInventory` — api-tree 전체 (점수 필터·상한 없음)
- `maxCandidates` (기본 80)
- 프리셋: Quick (design only), Standard (httpx only)

**판정:** high/medium finding 있으면 `fail`.

---

### 3.2 6-2 — 일괄적인 오류 처리 (로그인 enumeration)

**목표:** 로그인 실패 응답이 **계정 존재 여부를 구분하지 않는지** 검사 (v1 = 로그인 API).

**로그인 target 수집**

- **Inventory 자동 탐지** — `login_discovery_service.py`  
  api-tree POST + `/auth/login` 등 path 휴리스틱 + body에 email/password 필드
- `auth_probe_service.configured_login_entries()` → `resolve_login_entries()`

**시나리오 (각 login URL마다 httpx POST 3회)**

| 시나리오 | 입력 |
|----------|------|
| **A** | 존재 계정 + **틀린 PW** |
| **B** | 없는 계정 + **틀린 PW** |
| **C** | 없는 계정 + **맞는 PW** (Test Accounts 비밀번호) |

**판정** (`login_rules.py`)

- `compare_login_snapshot_set()` — A/B/C pairwise 비교
- HTTP status, JSON message/error/code, body fingerprint
- 전부 동일 → pass (info) · 하나라도 다름 → fail (medium)

**ZAP phase** (`zap_scan.py`, 기본 on)

- Active rule **40023** (Possible Username Enumeration, Beta add-on)
- login target마다 ZAP Context + `jsonBasedAuthentication` / `formBasedAuthentication`
- alerts 0 = 이슈 없음 (별도 finding 없음, stats에 `ZAP 완료 · findings 0`)

**필수 설정**

- Test Accounts (`data/test-accounts.json`) — A/C에 비밀번호 필요
- `config.yaml` → `auth.id_field` / `auth.pw_field` (POST body 키)

**Dashboard 옵션** (`g62DiagnosisOptions.ts`)

- `strict`, `timeout`, `probeAccountEmail`, `useZap`, `zapMaxMinutes`

---

### 3.3 7-1 — Client Request Method

**목표:** TRACE echo, OPTIONS Allow 위험 메서드, PUT/DELETE 노출.

**httpx** (`probes.py` + `method_rules.py`)

- **TRACE**: 2xx + body에 request echo → fail (high)
- **OPTIONS**: `Allow:` 헤더에 TRACE/TRACK/CONNECT → medium/high
- `strict_risky`: PUT/DELETE 허용도 fail 후보

**ZAP** (optional, `zap_scan.py`)

- Active scanner **90028** (Insecure HTTP Method) only
- httpx hit URL 우선 seed

**Dashboard 옵션:** probe_mode, strictRisky, useZap, timeout, extraProbePaths

---

### 3.4 7-2 — 파일 목록화 가능성

**목표:** Apache/nginx/IIS/Tomcat 등 **directory listing** 노출.

**wordlist** (`assets/`)

- `directory-wordlist.txt` — 공통 static/upload
- `directory-wordlist-comprehensive.txt` — WAS/CMS 대량 경로
- `2-2/forced-browse-download.txt` — 단일 segment
- api-tree (sample/full) — 디렉터리형 path + 상위 segment

각 path: `/path/` + `/path` (trailing slash 유/무)

**body 시그니처** (`listing_rules.py`)

- Apache `Index of`, nginx autoindex, IIS `- Directory listing`, Tomcat `<hr>` 등

**ZAP** (optional)

- Rule **0** (Directory Browsing), **10033**
- httpx hit URL seed 우선, Base URL당 `recurse=True` active scan

**Dashboard 옵션:** probe_mode (`base_only` | `sample` | `full`), useZap, zapMaxMinutes

---

### 3.5 7-3 — 서버 헤더정보 노출

**목표:** HTTP **응답 헤더**의 서버·스택·버전·환경 정보 (body stack trace는 6-1 범위).

**httpx** (`header_rules.py`)

- 고정 헤더 25종 (KISA + OWASP + ZAP passive 대표)
- 이름 휴리스틱 (`X-Custom-Version`, `version`, `powered` …)
- **strict 모드** (기본 on): 제품명만·환경명도 medium
- 동일 `(base, header, value)` → finding 1건 (`affected_urls` 집계)

**ZAP** (optional, **passive only**)

- Rules **10036** / **10036-1** / **10036-2** (Server), **10037** (X-Powered-By)
- active scan 없음 — seed → passive wait → alert 수집

**Dashboard 옵션:** strict, probe_mode, includeCdnHeaders, useZap

---

### 3.6 7-4 — 취약한 보안설정

**목표:** HTTP 응답에서 **보이는** 보안 설정 (OS/WAS 파일·방화벽은 제외).

**httpx** (`security_rules.py`)

| Check | 조건 |
|-------|------|
| HSTS | HTTPS인데 `Strict-Transport-Security` 없음 |
| CSP | `Content-Security-Policy` 없음 |
| X-Frame-Options | 없음 또는 `ALLOWALL` |
| X-Content-Type-Options | 없음 또는 `nosniff` 아님 |
| Referrer-Policy | 없음 (strict) |
| Cookie Secure/HttpOnly/SameSite | HTTPS + session cookie 취약 조합 |

**ZAP** (optional, passive)

- Rules 10035, 10038, 10020, 10021, 10054, 10063

**Dashboard 옵션:** strict, probe_mode, useZap

---

## 4. 프론트엔드 (Dashboard)

**진입:** `frontend/src/components/DiagnosisPage.tsx`

각 모듈마다:

| UI | 파일 |
|----|------|
| 옵션 타입·payload | `frontend/src/lib/g{22,62,71,72,73,74}DiagnosisOptions.ts` |
| 시작 다이얼로그 | `G{22,62,71,72,73,74}DiagnosisStartDialog.tsx` |
| 옵션 패널 | `G{22,62,71,72,73,74}DiagnosisOptionsPanel.tsx` |

**6-2 전용 Dashboard**

- `LoginEntriesPanel` — Verify 후 자동 탐지된 로그인 API·계정 매칭 결과 (읽기 전용)
- Test Accounts — A/C 시나리오용 계정·비밀번호

**결과 표시**

- 상단 stats 줄: probed/uniform/ZAP findings 등
- `GroupedFindingsPanel`: httpx · ZAP · info 섹션
- 6-2 `FindingEvidence`: A/B/C 시나리오별 status · email · message

---

## 5. 사전 준비 (공통)

1. **Build / Discover** — api-tree 생성 (`data/api-tree-ready.json` 등)
2. **Base URLs** — Dashboard에 스캔 대상 base 등록
3. **config.yaml** — `targets`, `auth`, `zap.proxy` (Docker: `http://zap:8090`)
4. **Test Accounts** — 2-2 인증 프로브, 6-2 A/C 시나리오
5. **Docker Compose** — ZAP 사용 시 `docker compose up` (backend + frontend + zap)

---

## 6. 실행 방법

### Dashboard

Diagnosis 페이지 → 해당 가이드라인 카드 → Run → 옵션 확인 → 실행

### API

```http
POST /api/diagnosis/modules/6-2/run
Content-Type: application/json

{
  "g62": {
    "strict": true,
    "timeout": 10,
    "zap_enabled": true,
    "zap_max_minutes": 5
  }
}
```

모듈별 body 키: `g22`, `g62`, `g71`, `g72`, `g73`, `g74`

### config.yaml 영구 옵션 (예)

```yaml
diagnosis_6_2:
  strict: true
  timeout: 10
  zap_enabled: true
  zap_max_minutes: 5

diagnosis_7_3:
  strict: true
  probe_mode: sample
  sample_size: 20
  zap_enabled: true
```

Run body 옵션이 config를 **run 단위로 override**합니다.

---

## 7. 테스트

```powershell
cd backend
python -m pytest tests/test_g22_candidates.py tests/test_g22_zap_hybrid.py -q
python -m pytest tests/test_g62_login.py tests/test_g62_zap.py -q
python -m pytest tests/test_g71_methods.py -q
python -m pytest tests/test_g72_listing.py -q
python -m pytest tests/test_g73_headers.py tests/test_g73_targets.py tests/test_g73_zap.py -q
python -m pytest tests/test_g74_security.py tests/test_g74_zap.py -q
python -m pytest tests/test_diagnosis.py -q
```

---

## 8. 모듈 간 관계·중복

| 주제 | 주 모듈 | 비고 |
|------|---------|------|
| Path Traversal / hidden file | **2-2** | 7-2 wordlist 일부 공유 |
| Directory listing | **7-2** | ZAP Rule 0 |
| Server header | **7-3** | 7-4와 분리 (disclosure vs misconfig) |
| Login enumeration | **6-2** | 3-3 계정 정보 파악과 연관 |
| Error page body leak | **6-1** (미구현) | 6-2는 로그인 failure uniformity |
| IDOR / auth matrix | 2-2 **v2** 예정 | 4-4와 `related_sections` 연계 예정 |

---

## 9. 디렉터리 빠른 참조

```
ARGUS_1/
  DIAGNOSIS_MODULES.md          ← 이 문서
  backend/
    diagnosis/
      base.py, registry.py, result.py
      modules/
        2-2/   … file download
        6-2/   … login enumeration
        7-1/   … HTTP methods
        7-2/   … directory listing
        7-3/   … header disclosure
        7-4/   … security headers / cookies
    app/
      routers/diagnosis.py
      services/
        diagnosis_service.py
        login_discovery_service.py
        zap_util.py
    data/
      api-tree-ready.json
      base-urls.json
      test-accounts.json
    tests/
      test_g22_*.py, test_g62_*.py, test_g71_*.py, …
  frontend/
    src/
      components/DiagnosisPage.tsx
      components/LoginEntriesPanel.tsx
      lib/g{22,62,71,72,73,74}DiagnosisOptions.ts
```

모듈별 더 세부적인 스코프·제외 항목은 각 `backend/diagnosis/modules/{id}/SCOPE.md`를 참고하세요.
