# ARGUS

Attack Surface Intelligence Platform — 공격 표면(api-tree) 수집·검증·가이드라인 진단 대시보드.

모노레포: **backend** (FastAPI) + **frontend** (Vite + React + Tailwind).

---

## 최상위 구조

```
ARGUS_1/
├── backend/          FastAPI API, inventory 빌드, 진단 엔진
├── frontend/         React 대시보드 UI
├── examples/         샘플 MD·swagger·URL/API 리스트
└── docker-compose.yml   backend + frontend + OWASP ZAP
```

---

## backend/

```
backend/
├── app/                      HTTP API 레이어
│   ├── main.py               FastAPI 앱 진입점
│   ├── config.py             config.yaml 로드
│   ├── schemas.py            요청/응답 Pydantic 모델
│   ├── routers/              REST 라우터
│   │   ├── inventory.py      Build / Discover / Verify / stats
│   │   ├── diagnosis.py      진단 catalog · run · report · replay
│   │   ├── base_urls.py      Base URL CRUD
│   │   ├── test_accounts.py  테스트 계정
│   │   ├── login_endpoints.py
│   │   └── redirect_sink.py  1-5 open redirect sink
│   └── services/             비즈니스 로직 (라우터 → 서비스 → diagnosis/inventory)
│       ├── inventory_service.py
│       ├── verify_service.py
│       ├── discover_service.py
│       ├── diagnosis_service.py
│       ├── auth_probe_service.py
│       └── ...
│
├── inventory/                api-tree 생성·병합·태깅
│   ├── load.py                 api-tree JSON 로드
│   ├── merge.py                소스 병합
│   ├── probe_build.py          Build 파이프라인
│   ├── schema.py               Endpoint / ApiTree 타입
│   ├── upload_retention.py     uploads 배치 보존 (최신 5개)
│   ├── upload_batch.py         uploads/{uuid}/ manifest · openapi 경로
│   └── sources/                입력 소스 파서
│       ├── markdown.py
│       ├── openapi.py
│       ├── url_list.py
│       └── txt_list.py
│
├── diagnosis/                  가이드라인 진단 프레임워크
│   ├── registry.py             modules/*/module.py 자동 등록
│   ├── catalog.py              섹션 ID · 제목 · 챕터 목록
│   ├── base.py                 DiagnosisModule 베이스
│   ├── context.py              DiagnosisContext (config + data_dir)
│   ├── paths.py                리포트 경로: data/report/{id}/
│   ├── result.py               SectionReport · Finding
│   ├── probe_auth.py           httpx 인증 프로브 헬퍼
│   ├── progress_reporter.py    진행률 보고
│   ├── replay/                 finding evidence 재현
│   └── modules/                섹션별 진단 구현 (1-1 … 8-1, 아래 전체 목록)
│       ├── 1-1/                (병합 대기중) XSS / CSRF
│       ├── 1-2/                (병합 대기중) Injection
│       ├── 1-3/                (추후 검토) 파라미터·Hidden 조작
│       ├── 1-4/                (병합 대기중) SSRF / File Inclusion
│       ├── 1-5/                (구현) 검증되지 않은 리다이렉트
│       ├── 1-6/                (병합 대기중) 입력 값 크기·무결성
│       ├── 2-1/                (병합 대기중) 악성코드파일 업로드
│       ├── 2-2/                (구현) 중요 정보 파일 다운로드
│       ├── 3-1/                (추후 검토) 패스워드 정책
│       ├── 3-2/                (구현) 인증 실패 횟수 제한
│       ├── 3-3/                (추후 검토) 계정 정보 파악
│       ├── 3-4/                (구현) 관리자 페이지 분리
│       ├── 3-5/                (구현) 검색엔진 정보 노출
│       ├── 3-6/                (구현) 백업·테스트 파일
│       ├── 4-1/                (구현) 쿠키·Web Storage 조작
│       ├── 4-2/                (구현) 세션·토큰 안전성
│       ├── 4-3/                (추후 검토) 접근제어 우회
│       ├── 4-4/                (추후 검토) 비인증 중요 page 접근
│       ├── 4-5/                (추후 검토) 일반계정 권한 상승
│       ├── 5-1/                (추후 검토) 소스코드 주요정보 노출
│       ├── 5-2/                (구현) 요청·응답 주요정보
│       ├── 6-1/                (구현) 오류페이지 정보 노출
│       ├── 6-2/                (구현) 일괄 오류 처리 페이지
│       ├── 7-1/                (구현) Client Request Method
│       ├── 7-2/                (구현) 파일 목록화
│       ├── 7-3/                (구현) 서버 헤더정보 노출
│       ├── 7-4/                (구현) 취약한 보안설정
│       └── 8-1/                (추후 검토) 기타 취약점
│
├── integrations/
│   └── zap/                    OWASP ZAP API 클라이언트
│       └── client.py
│
├── parsers/
│   └── parse_endpoints.py
│
├── scripts/                    유틸·코드 생성
│   ├── gen_diagnosis_modules.py
│   └── run_evidence_replay.py
│
├── tests/                      pytest (test_g*.py = 섹션별)
│
├── data/                       런타임 산출물 (gitignore 일부)
│   ├── api-tree.json           Build 결과
│   ├── api-tree-ready.json
│   ├── api-tree-verified.json  Verify 결과
│   ├── verify-report.json
│   ├── base-urls.json
│   ├── test-accounts.json
│   ├── uploads/{uuid}/         Build 업로드 배치 (최대 5개 유지)
│   │   ├── manifest.json       이번 배치에 포함된 파일 목록
│   │   ├── url-list.txt        (선택)
│   │   ├── api-list.txt        (선택)
│   │   └── openapi.json        (선택) Dashboard Swagger 업로드본
│   └── report/                 진단 산출물 (섹션 ID = 모듈 번호)
│       └── {section-id}/       예: 1-1, 2-2, 4-1 …
│           ├── latest.yaml     UI/API 리포트 (필수)
│           ├── evidence/       replay·HTTP 증적 (선택)
│           └── …               scanner 중간 산출물 (선택, 모듈별)
│
├── config.yaml                 로컬 설정 (MD·OpenAPI 경로, auth 등)
├── config.docker.yaml          Docker용 설정
├── Dockerfile
└── requirements.txt
```

### diagnosis/modules/

KISA 가이드라인 **1-1 … 8-1** 항목마다 폴더 하나. 폴더명 = 섹션 ID.

| 상태 | 의미 |
|------|------|
| **구현** | `scanner.py` 등 실제 진단 로직 · UI에서 **진단 시작** 가능 |
| **추후 검토** | `module.py` + `manifest.yaml`만 (`StubDiagnosisModule`) · 등록됨, 미구현 |
| **병합 대기중** | `.gitkeep`만 · `module.py` 없음 → registry **미등록** |

#### 챕터 1 — 입력 데이터 검증 및 표현

```
modules/
├── 1-1/    XSS / CSRF 공격 가능성                          [병합 대기중]
├── 1-2/    삽입(Injection) 공격 가능성                     [병합 대기중]
├── 1-3/    파라미터 값 및 Hidden 필드 조작 가능성           [추후 검토]
├── 1-4/    SSRF / File Inclusion 공격 가능성                [병합 대기중]
├── 1-5/    검증되지 않은 리다이렉트와 포워드               [구현] httpx+zap
└── 1-6/    입력 값 크기 및 무결성 검증 오류                 [병합 대기중]
```

#### 챕터 2 — 파일 업·다운로드

```
├── 2-1/    악성코드파일 업로드                             [병합 대기중]
└── 2-2/    중요 정보 파일 다운로드 가능성                  [구현] httpx+zap
```

#### 챕터 3 — 인증·접근통제

```
├── 3-1/    패스워드 정책 유무 및 반영 여부                  [추후 검토]
├── 3-2/    인증 실패 횟수 제한                             [구현] httpx
├── 3-3/    계정 정보 파악 가능성                            [추후 검토]
├── 3-4/    관리자 페이지 분리 여부                          [구현] inventory
├── 3-5/    검색엔진 정보 노출 가능성                        [구현] httpx
└── 3-6/    백업 파일 및 테스트 파일 존재 여부               [구현] httpx
```

#### 챕터 4 — 세션·접근제어

```
├── 4-1/    쿠키 및 Web Storage 조작 가능성                  [구현] httpx
├── 4-2/    인증(세션 및 토큰) 값 안전성 설정 여부            [구현] httpx
├── 4-3/    접근제어 우회 가능성 확인                        [추후 검토]
├── 4-4/    비인증 상태로 중요 page 접근 가능성              [추후 검토]
└── 4-5/    일반계정 권한 상승 가능성                        [추후 검토]
```

#### 챕터 5 — 데이터 보호

```
├── 5-1/    소스코드 내 주요정보 노출 여부                   [추후 검토]
└── 5-2/    요청 및 응답 값 내 주요정보 포함여부             [구현] httpx
```

#### 챕터 6 — 오류 처리

```
├── 6-1/    오류페이지를 통한 정보 노출 여부                  [구현] httpx
└── 6-2/    일괄적인 오류 처리 페이지 존재 여부              [구현] httpx+zap
```

#### 챕터 7 — 서버 보안

```
├── 7-1/    Client Request Method                            [구현] httpx+zap
├── 7-2/    파일 목록화 가능성                               [구현] httpx+zap
├── 7-3/    서버 헤더정보 노출                               [구현] httpx+zap
└── 7-4/    취약한 보안설정                                  [구현] httpx+zap
```

#### 챕터 8 — 기타

```
└── 8-1/    취약점 진단 항목에 정의되지 않은 취약점           [추후 검토]
```

### modules/{section-id}/ 내부 (구현 모듈 예: 1-5)

```
modules/1-5/
├── module.py                 DiagnosisModule 구현 · `module` export
├── manifest.yaml             title, chapter, engine (httpx/zap 등)
├── scanner.py                오케스트레이션 (run_g15_scan)
├── targets.py                probe 대상 수집
├── probes.py                 httpx 프로브
├── *_rules.py                finding 판정 규칙
├── zap_scan.py               (선택) ZAP active scan
└── SCOPE.md                  (선택) 범위 메모
```

추후 검토 모듈은 보통 `module.py` + `manifest.yaml`만 있습니다.  
병합 대기중 폴더는 `.gitkeep`만 있으며 `module.py`가 없어 registry에 올라가지 않습니다.

진단 **코드**는 `diagnosis/modules/`에, **리포트·증적·추출 자료**는 `data/report/{id}/` 아래에 저장합니다 (`latest.yaml` 필수, 나머지 선택).

---

## frontend/

```
frontend/
├── src/
│   ├── App.tsx                 레이아웃 · 사이드바 · Inventory / Verify / Diagnosis 탭
│   ├── main.tsx
│   ├── types.ts                API 타입 · DiagnosisRunSectionRequest 등
│   ├── index.css
│   │
│   ├── lib/
│   │   ├── api.ts              backend REST 클라이언트
│   │   ├── guidelineSections.ts
│   │   ├── diagnosisRegistry.ts
│   │   ├── verifyOptions.ts
│   │   └── g{NN}DiagnosisOptions.ts   섹션별 진단 옵션 · 프리셋 · payload
│   │
│   ├── components/
│   │   ├── DiagnosisPage.tsx           가이드라인 진단 메인
│   │   ├── G{NN}DiagnosisStartDialog.tsx  3탭 시작 (최소/전체/수동)
│   │   ├── G{NN}DiagnosisOptionsPanel.tsx
│   │   ├── diagnosis/
│   │   │   └── DiagnosisReportPanel.tsx
│   │   ├── BuildSourcePanel.tsx
│   │   ├── BaseUrlsPanel.tsx
│   │   ├── TestAccountsPanel.tsx
│   │   ├── LoginEndpointsPanel.tsx
│   │   ├── LoginEntriesPanel.tsx
│   │   ├── VerifyStartDialog.tsx
│   │   ├── VerifyResultsPanel.tsx
│   │   ├── EndpointTable.tsx
│   │   └── ui/                         공통 UI
│   │
│   ├── hooks/
│   │   └── useProgressPoll.ts
│   │
│   └── assets/
│
├── public/
├── scripts/                    UI 유지보수 스크립트
├── Dockerfile
├── nginx.conf                  프로덕션 정적 서빙
├── vite.config.ts
└── package.json
```

진단 UI 패턴:

- 옵션이 있는 섹션 → **진단 시작** 클릭 시 `G{NN}DiagnosisStartDialog` (최소 / 전체 / 수동)
- 옵션 정의 → `src/lib/g{NN}DiagnosisOptions.ts`
- 실행 → `POST /diagnosis/modules/{id}/run` body `{ g{NN}: { ... } }`

---

## examples/

Dashboard **Build** 업로드 테스트용 샘플 (Swagger·URL/API 리스트).  
실제 운영 spec은 `backend/data/uploads/{uuid}/`에 저장됩니다.

```
examples/
├── swagger.json          Build → Swagger 업로드 테스트용
├── onde-api-list.txt
├── onde-url-list.txt
├── api-list.example.txt
└── url-list.example.txt
```

---

## Docker 볼륨 (참고)

| 호스트 | 컨테이너 | 용도 |
|--------|----------|------|
| `../` (Zap 워크스페이스) | `/workspace` (ro) | Onde MD 읽기 (config `inventory.markdown.path`) |
| `backend/data` | `/app/data` | api-tree · report · uploads (Swagger 포함) |
| `backend/diagnosis/modules` | `/app/diagnosis/modules` | 진단 모듈 코드 동기화 |

서비스 포트: frontend **5174**, backend **8001**, ZAP **8090**.

---

## 팀원 가이드 — 병합 대기중 모듈 독립 통합

각자 ZAP·httpx로 **별도 저장소/브랜치에서 개발한 진단 로직**을 ARGUS에 합칠 때 읽는 문서입니다.

### 원칙 (꼭 지킬 것)

1. **자기 번호 폴더만 수정** — `backend/diagnosis/modules/{본인-ID}/` 안에서만 작업합니다.
2. **다른 번호 폴더·공통 모듈은 건드리지 않음** — `diagnosis/registry.py`, `inventory/`, 다른 사람의 `1-5/` 등은 수정하지 않습니다.
3. **공통 코드 재사용은 선택** — `inventory.load`, `integrations/zap`, `probe_auth` 등을 **가져다 써도 되고**, 본인 httpx/ZAP 스크립트만 넣어도 됩니다.
4. **registry 수동 등록 불필요** — `{본인-ID}/module.py`가 있으면 서버 재시작 시 자동 등록됩니다.

---

### 병합 대기중 번호 (폴더만 있음)

지금 `module.py`가 **없어서** UI catalog에 `engine: missing`으로 보이는 항목입니다. **여기에 본인 코드를 넣으면 됩니다.**

| ID | 항목 |
|----|------|
| `1-1` | XSS / CSRF 공격 가능성 |
| `1-2` | 삽입(Injection) 공격 가능성 |
| `1-4` | SSRF / File Inclusion 공격 가능성 |
| `1-6` | 입력 값 크기 및 무결성 검증 오류 |
| `2-1` | 악성코드파일 업로드 |

폴더 상태: `.gitkeep`만 있음 → **`module.py` + `manifest.yaml` (+ scanner 등) 추가하면 끝.**

---

### 1단계 — 본인 폴더에 파일 배치

```text
backend/diagnosis/modules/1-1/          ← 예: 1-1 담당者
├── manifest.yaml                       ← 필수
├── module.py                           ← 필수 · 마지막에 module = ... export
├── scanner.py                          ← 권장 · run_g11_scan(ctx) 진입점
├── zap_scan.py                         ← ZAP 쓰면
├── probes.py / *_rules.py / targets.py ← 본인 구조대로
└── assets/                             ← wordlist, zap-policy.yaml 등
```

**하지 말 것**

- `modules/1-1/reports/` 아래에 리포트 저장 (구 방식) → **`data/report/1-1/`** 사용
- 다른 ID 폴더에 파일 복사·덮어쓰기
- `backend/app/` 공통 라우터를 본인 로직으로 크게 수정

---

### 2단계 — manifest.yaml

```yaml
id: "1-1"
title: "XSS / CSRF 공격 가능성"
chapter: 1
implemented: true          # 실제 진단 가능하면 true
diagnosable: true          # UI/API에서 run 허용
engine: httpx+zap          # httpx / zap / httpx+zap / inventory 등 표시용
```

- `implemented: false` → UI에 “미구현”으로만 보임
- `diagnosable: false` → `POST .../run` 시 400 (수동 확인 항목용, 3-1처럼)

---

### 3단계 — module.py 최소 골격

공통 `DiagnosisModule`을 **상속**하는 패턴 (다른 번호 코드와 동일 계약).  
본인 scanner만 교체하면 됩니다.

```python
"""Diagnosis module 1-1: XSS / CSRF."""

from __future__ import annotations
import importlib.util
from pathlib import Path
import yaml

from diagnosis.base import DiagnosisModule
from diagnosis.context import DiagnosisContext
from diagnosis.result import DiagnosisFinding, SectionReport, utc_now_iso

_MODULE_DIR = Path(__file__).resolve().parent

def _load_scanner():
    spec = importlib.util.spec_from_file_location("diag_g11_scanner", _MODULE_DIR / "scanner.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class G11Module(DiagnosisModule):
    section_id = "1-1"
    title = "XSS / CSRF 공격 가능성"
    chapter = 1
    implemented = True
    engine = "httpx+zap"

    def __init__(self, module_dir: Path) -> None:
        self.module_dir = module_dir

    def run(self, ctx: DiagnosisContext) -> SectionReport:
        scanner = _load_scanner()
        result = scanner.run_g11_scan(ctx, self.module_dir)  # 본인 함수명

        report = SectionReport(
            section_id=self.section_id,
            title=self.title,
            chapter=self.chapter,
            status=result.status,       # pass | warn | fail | skipped | error
            implemented=True,
            findings=result.findings,
            message=result.message,
            checked_at=utc_now_iso(),
        )
        self.save_report(ctx, report)   # → data/report/1-1/latest.yaml
        return report

module = G11Module(_MODULE_DIR)        # registry가 이 이름을 찾음
```

**완전 독립**으로 가도 됩니다: scanner 안에서 httpx·ZAP Python 클라이언트만 쓰고, 위 `run()`에서 `findings`/`status`만 맞춰 주면 UI·API는 동작합니다.

**참고만 하고 싶을 때** — 같은 패턴의 구현 예시 (수정 금지, 읽기만):

- ZAP + httpx: `modules/1-5/`, `modules/2-2/`
- httpx only: `modules/3-2/`, `modules/4-2/`
- inventory 정적: `modules/3-4/`

---

### 4단계 — scanner에서 Attack Surface 데이터 읽기

진단은 **Verify까지 끝난 뒤** 돌리는 것을 권장합니다. (Dashboard → Build → Verify)

#### 런타임에 주어지는 것: `DiagnosisContext`

| 필드 | 내용 |
|------|------|
| `ctx.data_dir` | `backend/data/` (Docker: `/app/data`) |
| `ctx.raw_config` | `config.yaml` 전체 (auth, zap, `diagnosis_1_1` 등) |
| `ctx.config` | inventory용 dict (base URL 등) |

#### 꼭 알아둘 파일 (`ctx.data_dir` 기준)

| 파일 | 언제 생김 | 진단에서 쓰는 법 |
|------|-----------|------------------|
| `api-tree-verified.json` | **Verify 성공 후** | **1순위** — 검증된 API·경로·파라미터 트리 |
| `api-tree-ready.json` | Build 후 | verified 없을 때 fallback |
| `api-tree.json` | Build/Verify | legacy fallback |
| `verify-report.json` | Verify 후 | 엔드포인트별 confirmed/rejected, **`login_entry_report`**, `account_auths` |
| `test-accounts.json` | Dashboard Test Accounts 저장 | 로그인·세션 probe |
| `base-urls.json` | Dashboard Base URLs | 프론트/ API base |
| `zap-inventory-bundle.json` | Discover(ZAP) 후 | 업로드 OpenAPI 경로 메타 |

#### api-tree 로드 (공통 helper — **선택**)

```python
from inventory.load import load_api_tree

tree = load_api_tree(ctx.data_dir)
if tree is None:
    return ScanResult(status="skipped", message="api-tree 없음 — Build/Verify 먼저")
for ep in tree.endpoints:
    ...  # ep.method, ep.path, ep.base_url, ep.params ...
```

`load_api_tree`는 내부적으로 **`verified → ready → legacy` 순**으로 파일을 고릅니다.

#### Swagger / OpenAPI (Dashboard 업로드 전용)

로컬 `config.yaml`의 `inventory.openapi.path` **는 사용하지 않습니다.**  
Attack Surface 탭 **Build**에서 Swagger 파일을 선택하면:

1. `data/uploads/{uuid}/` 배치 폴더 생성
2. `openapi.json` (또는 `.yaml`) 저장
3. `manifest.json`에 파일 목록 기록
4. api-tree 빌드 후 `zap-inventory-bundle.json`에 **상대 경로** `uploads/{uuid}/openapi.*` 기록
5. 성공 시 오래된 배치 자동 정리 (최신 5개만 유지)

Discover(ZAP) · 진단 코드에서 spec이 필요하면:

```python
from inventory.load import find_openapi_spec

spec_path = find_openapi_spec(ctx.data_dir)  # bundle → uploads 최신 순
```

`config.yaml`의 `inventory.openapi.base_url`은 **업로드한 spec에 servers URL이 없을 때** API base 힌트로만 씁니다 (path는 비움).

---

#### verify-report / 로그인 매트릭스 (인증·쿠키·세션 진단 시)

```python
import json
from pathlib import Path

verify_path = ctx.data_dir / "verify-report.json"
if verify_path.is_file():
    raw = json.loads(verify_path.read_text(encoding="utf-8"))
    login_report = raw.get("login_entry_report")  # login URL · 세션 · Set-Cookie
    account_auths = raw.get("account_auths") or []
```

4-1, 4-2, 3-4 `targets.py`에 같은 패턴이 있습니다 (복사해도 되고, 직접 JSON 읽어도 됨).

Build 응답 `artifacts` 예시:

```json
{
  "upload_batch": "uploads/a1b2c3...",
  "openapi_upload": "uploads/a1b2c3.../openapi.json",
  "zap_bundle": "zap-inventory-bundle.json"
}
```

---

### 5단계 — ZAP 사용 (본인 모듈 안에서)

Docker Compose 기준 ZAP API: `http://zap:8090` (컨테이너 내부) / 호스트 `8090`.

`ctx.raw_config.get("zap")` 또는 환경변수 `ZAP_PROXY`:

```yaml
# config.docker.yaml (이미 있음 — 본인 섹션만 추가 가능)
zap:
  proxy: "http://zap:8090"
  api_key: ""
  auto_wait: true
  wait_seconds: 90
```

**선택 A — 기존 helper 참고 (2-2, 1-5 `zap_scan.py`)**

- `app.services.zap_util`: `connect_zap`, `ensure_zap_proxy`, `apply_auth_to_zap`, `reset_zap_workspace`
- `integrations.zap.client`: 저수준 ZAP JSON API

**선택 B — 완전 독립**

- 본인 repo의 ZAP 스크립트를 `zap_scan.py`로 그대로 두고 `scanner.py`에서 호출
- proxy URL만 Docker/로컬에 맞게 설정

ZAP active scan 전 **대상 URL을 api-tree에서 뽑아** seed로 넣으면 됩니다 (2-2 `seed_urls` 패턴 참고).

---

### 6단계 — 증적 · 산출물 저장 (`data/report/{ID}/`)

진단 결과·증적·중간 산출물은 **`backend/data/report/{본인-ID}/`** 아래에 모읍니다.  
`diagnosis/modules/{ID}/` 안이 아니라 **`data/report/`** — Docker·로컬·다른 모듈이 같은 경로로 읽을 수 있게 하기 위함입니다.

> **현재 상태:** `latest.yaml` 저장은 대부분 모듈에서 동작합니다.  
> `evidence/` · 중간 JSON/YAML 등 **증적 수집은 2-2 등 일부만 구현**되어 있고, 나머지는 아직 비어 있어도 됩니다.  
> 아래는 **팀 공통으로 맞춰 갈 규칙**입니다.

#### 디렉터리 규칙

```
data/report/{ID}/
├── latest.yaml              ← UI/API 리포트 (필수) · save_report()
├── evidence/                ← replay·요청/응답 캡처 (선택)
│   └── {finding-id}/        ← finding 하나당 하위 폴더 (2-2 패턴)
├── exports/                 ← 표·CSV·요약 JSON 등 뽑아낸 자료 (선택, 이름은 모듈 자유)
└── …                        ← probe 로그, ZAP 덤프 등 (선택)
```

| 산출물 | 경로 | 방법 |
|--------|------|------|
| 진단 리포트 | `data/report/{ID}/latest.yaml` | `self.save_report(ctx, report)` |
| replay evidence | `data/report/{ID}/evidence/{finding-id}/` | `section_evidence_dir(ctx.data_dir, "{ID}")` |
| 중간·추출 자료 | `data/report/{ID}/` 하위 임의 파일 | `section_report_dir(ctx.data_dir, "{ID}")` 에 직접 저장 |

경로 helper (`diagnosis/paths.py`):

```python
from diagnosis.paths import section_report_dir, section_report_path, section_evidence_dir

out_dir = section_report_dir(ctx.data_dir, "1-1")   # data/report/1-1/
report_path = section_report_path(ctx.data_dir, "1-1")  # .../latest.yaml
evidence_root = section_evidence_dir(ctx.data_dir, "1-1")  # .../evidence/
evidence_root.mkdir(parents=True, exist_ok=True)
(out_dir / "exports" / "probe-summary.json").write_text("...", encoding="utf-8")
```

#### Finding · status (latest.yaml)

```python
DiagnosisFinding(
    severity="high",           # high | medium | low | info
    message="XSS reflected in ...",
    evidence={"rule_id": "1-1-xss-reflected", "url": "...", ...},  # UI 요약용 (파일 경로도 OK)
)
```

`status`: `pass` / `warn` / `fail` / `skipped` / `error` — UI 배지에 그대로 반영됩니다.

#### 다른 모듈·후속 단계에서 읽기

같은 머신의 `ctx.data_dir`(= `backend/data`)를 기준으로 **다른 번호 폴더 리포트**를 읽을 수 있습니다.

```python
import yaml
from diagnosis.paths import section_report_path

other = section_report_path(ctx.data_dir, "2-2")
if other.is_file():
    prior = yaml.safe_load(other.read_text(encoding="utf-8"))
    # findings · evidence 파일 경로 등 활용
```

**하지 말 것:** `modules/{ID}/reports/` (구 2-2 경로) — 신규 코드는 `data/report/{ID}/`만 사용.

---

### 7단계 — UI에서 본인 탭 사용

1. 브라우저 **http://localhost:5174** → 사이드바 **Diagnosis**
2. 챕터 펼치기 → **본인 ID** 행 (예: `1-1 XSS / CSRF`)
3. **진단 시작** 클릭

| UI 동작 | 조건 |
|---------|------|
| **바로 실행** | `DiagnosisPage`에 전용 StartDialog가 **없는** 번호 — 클릭 즉시 `POST /diagnosis/modules/{id}/run` |
| **3탭 다이얼로그** (최소/전체/수동) | 1-5, 2-2, 3-2 … 처럼 `G{NN}DiagnosisStartDialog`가 이미 연결된 번호만 |

**병합 대기중 번호(1-1 등)는 Dialog 없음 → 등록 후 바로 실행**됩니다.  
옵션이 필요하면 아래 “선택: 프론트 옵션” 참고.

4. 실행 중 해당 행 펼치면 **진행률·요약** 표시
5. 완료 후 **findings** · `latest.yaml` 내용이 리포트 패널에 표시

**사전 준비 (Dashboard 탭)**

| 메뉴 | 용도 |
|------|------|
| Build | api-tree 생성 |
| Base URLs / Test Accounts / Login | Verify·인증 probe |
| Verify | **api-tree-verified.json** + **verify-report.json** 생성 |

---

### 8단계 — API만으로 테스트 (프론트·공통 코드 수정 없이)

```http
POST http://localhost:8001/diagnosis/modules/1-1/run
Content-Type: application/json

{}
```

Swagger: **http://localhost:8001/docs** → `diagnosis` → `POST /diagnosis/modules/{section_id}/run`

```http
GET http://localhost:8001/diagnosis/modules/1-1/report
GET http://localhost:8001/diagnosis/catalog
```

catalog에서 본인 ID의 `registered: true`, `implemented: true` 확인.

---

### 9단계 — 실행 옵션 (선택)

**A. config.yaml만 사용 (공통 API 스키마 수정 없음 — 권장)**

`config.yaml` / `config.docker.yaml`에 본인 섹션 블록 추가:

```yaml
diagnosis_1_1:
  probe_mode: sample
  sample_size: 40
  zap_enabled: true
  zap_max_minutes: 15
```

scanner에서:

```python
cfg = (ctx.raw_config or {}).get("diagnosis_1_1") or {}
zap_on = bool(cfg.get("zap_enabled", False))
```

다른 번호의 `diagnosis_3_2`, `diagnosis_4_2`와 동일 패턴입니다.

**B. API body로 run마다 옵션 (프론트 3탭까지 원할 때)**

본인 번호 전용으로 **새 파일만** 추가:

- `backend/app/schemas.py` — `DiagnosisG11RunOptions` + `DiagnosisRunSectionRequest.g11` 필드 **한 블록 추가**
- `backend/app/services/diagnosis_service.py` — `g11_options` 분기 **한 블록 추가**
- `backend/app/routers/diagnosis.py` — body 파싱 **한 블록 추가**
- `frontend/src/lib/g11DiagnosisOptions.ts` (신규)
- `frontend/src/components/G11DiagnosisStartDialog.tsx` (신규)
- `frontend/src/components/DiagnosisPage.tsx` — **본인 ID 분기만** 추가 (다른 번호 코드는 변경하지 않음)

기존 1-5, 2-2 Dialog 파일을 **복사해서 이름·필드만 바꾸면** 됩니다.

---

### 10단계 — Docker 반영

`docker-compose.yml`이 이미 마운트:

```yaml
- ./backend/diagnosis/modules:/app/diagnosis/modules
```

→ **본인 폴더만 수정하면** backend 재시작으로 코드 반영:

```powershell
docker compose restart backend
# 또는
docker compose up -d --build backend
```

`data/`는 호스트 `backend/data`와 공유 → Verify 결과·리포트는 컨테이너/로컬 동일.

---

### 통합 체크리스트

- [ ] `backend/diagnosis/modules/{ID}/module.py` 존재 · `module = ...` export
- [ ] `manifest.yaml` · `implemented: true`
- [ ] Verify 후 `data/api-tree-verified.json` 존재
- [ ] (인증 필요 시) `data/verify-report.json` · Test Accounts 설정
- [ ] (ZAP 사용 시) `docker compose`에서 `zap` healthy · proxy URL 일치
- [ ] `POST /diagnosis/modules/{ID}/run` → 200
- [ ] `data/report/{ID}/latest.yaml` 생성
- [ ] UI Diagnosis 탭에서 findings 확인
- [ ] **다른 ID 폴더 diff 없음** (`git status`로 확인)

---

### 자주 묻는 것

**Q. 공통 모듈 꼭 써야 하나요?**  
A. 아니요. `DiagnosisContext` + `SectionReport` + `save_report`만 맞추면 됩니다.

**Q. 병합 대기중 말고 추후 검토(1-3 등) 번호에 넣어도 되나요?**  
A. 가능하지만 **담당 ID가 정해져 있으면 해당 폴더만** 쓰세요. 추후 검토 폴더는 `StubDiagnosisModule` + `diagnosable: false`인 경우 run이 막혀 있으므로, 통합 시 `manifest`에서 `diagnosable: true`, `implemented: true`로 바꿔야 합니다.

**Q. swagger.json을 진단 코드에서 직접 파싱해도 되나요?**  
A. 가능하지만 권장하지 않습니다. Swagger는 **Dashboard Build 업로드** → `data/uploads/{uuid}/openapi.*`에 저장되고, Build 결과는 `api-tree-verified.json`에 merge됩니다. spec 원본이 필요하면 `find_openapi_spec(ctx.data_dir)`로 배치 경로를 찾으세요.

**Q. evidence / 중간 산출물 폴더는 언제 생기나요?**  
A. **규칙상** `data/report/{ID}/evidence/` · `exports/` 등에 두면 됩니다. replay·scanner가 파일을 쓸 때 생성하고, **아직 대부분 모듈은 `latest.yaml`만** 있습니다. 본인 모듈에서 증적이 필요하면 `section_report_dir` / `section_evidence_dir`로 같은 위치에 추가하세요.

**Q. 기존 구현 코드를 건드리면?**  
A. PR 리뷰에서 reject. **본인 `{ID}/` 디렉터리 + (선택) 본인 g{NN} 프론트 + 본인 config 블록**만 커밋하세요.

