# 플랫폼 독립적 인벤토리 처리 변경 내역

## 목적

ARGUS가 ONDE, MATE 또는 특정 포트·프레임워크를 알지 않은 상태에서 사용자가 제공한 다음 입력만으로 `api-tree.json`을 구성하도록 수정했다.

- Base URL과 그 역할
- API List
- URL List
- Swagger/OpenAPI

플랫폼 이름·파일명·포트로 대상을 판별하는 로직은 추가하지 않았다.

## 최종 범위

다음은 이번 작업에서 제외했다.

- `data/runs/{run_id}` 구조
- “새 진단 시작”, “현재 진단 초기화” UI
- 로그인 후보 탐색·인증 시도·토큰 감지 로직 변경
- `backend/diagnosis/modules/**` 변경
- `backend/screenshot/modules/**` 변경

로그인 탐색은 기존처럼 API Tree, 설정, 대시보드 확정 URL을 사용하도록 유지했다.

## 1. 플랫폼 전용 기본 설정 제거

변경 파일:

- `backend/config.yaml`
- `backend/config.docker.yaml`
- `backend/app/config.py`

기본 설정에서 다음 대상 정보를 제거했다.

- `app_name: onde-pilot`
- ONDE Markdown 문서 경로
- 기본 API/Frontend URL
- 기본 target

기본값은 빈 인벤토리 상태다.

```yaml
app_name: ''
targets: []

inventory:
  markdown:
    enabled: false
    path: ''
    include_frontend_routes: false
    frontend_base_url: ''
  openapi:
    enabled: false
    path: ''
    base_url: ''
  url_list:
    enabled: false
    path: data/inventory-urls.json
  base_urls: []
```

ZAP, discover, timeout, 진단 항목 옵션 같은 ARGUS 실행 정책은 유지했다.

## 2. Base URL 역할 추가

변경 파일:

- `backend/app/schemas.py`
- `backend/app/services/base_urls_service.py`
- `frontend/src/types.ts`
- `frontend/src/components/BaseUrlsPanel.tsx`
- `frontend/src/App.tsx`

Base URL 입력에 `kind`를 추가했다.

```json
{
  "id": "target-id",
  "url": "http://example.test:8080",
  "kind": "frontend"
}
```

지원 역할:

- `api`
- `frontend`
- `api-and-frontend`

기존 `base-urls.json`에 `kind`가 없는 항목은 하위 호환을 위해 `api`로 읽힌다. 기존 작업 데이터를 계속 사용하려면 Base URLs 화면에서 각 URL의 역할을 한 번 선택해 저장해야 한다. ARGUS가 포트로 자동 추정하지는 않는다.

이전의 `5173이면 frontend`, `8080이면 api` 같은 포트 추정을 제거했다. 프런트가 8080이고 API가 3000이어도 사용자가 선택한 역할대로 처리된다.

Docker 설정을 동기화할 때는 API 역할 URL만 `targets`/OpenAPI base URL에 반영하고, Frontend 역할 URL만 frontend base URL에 반영한다.

## 3. 소스별 Base URL 분리

변경 파일:

- `backend/app/routers/inventory.py`
- `backend/app/services/inventory_service.py`
- `backend/inventory/sources/txt_list.py`
- `backend/inventory/sources/openapi.py`

이전에는 모든 소스에 같은 `base_urls`를 전달했다.

```text
API List × API URL
API List × Frontend URL
URL List × API URL
URL List × Frontend URL
```

수정 후에는 아래 규칙을 사용한다.

```text
API List  → API 역할 Base URL
OpenAPI   → OpenAPI servers[].url 또는 API 역할 Base URL
URL List  → Frontend 역할 Base URL
```

상대 경로 URL List에 Frontend Base URL이 없으면 `localhost:5173`을 임의로 생성하지 않고 해당 항목을 미해결 상태로 둔다. OpenAPI에도 유효한 server/API Base URL이 없으면 임의 localhost를 생성하지 않는다.

## 4. API List·OpenAPI 중복 병합

기존 `merge_trees()`를 그대로 사용한다. 다음 키가 같으면 하나의 endpoint로 병합된다.

```text
base_url + HTTP method + path
```

결과의 `sources`에는 둘 다 남는다.

```json
{
  "method": "POST",
  "path": "/api/auth/login",
  "base_url": "http://api.example",
  "sources": ["api_list", "openapi:openapi"]
}
```

## 5. 새 인벤토리 빌드 시 이전 파생 결과 무효화

변경 파일:

- `backend/app/routers/inventory.py`

새 endpoint 인벤토리 빌드가 성공하면 이전 대상에서 만들어진 다음 파생 결과를 무효화한다.

- `api-tree-verified.json`
- `verify-report.json`
- `discover-progress.json`
- `data/report/` 아래의 이전 진단 결과·evidence

사용자가 직접 저장한 다음 입력은 자동 삭제하지 않는다.

- Base URL
- 테스트 계정
- 로그인 엔드포인트

로그인 로직은 기존 구조를 유지했다.

## 6. 새 설치의 초기 데이터

변경 파일:

- `backend/data/login-endpoints.json`
- `backend/data/download-endpoints.json`
- `backend/data/.gitignore`

저장소에 들어 있던 특정 대상의 로그인·다운로드 endpoint 기본값을 빈 목록으로 변경했다.

```json
{
  "endpoints": []
}
```

런타임에 생성되는 Base URL, 계정, endpoint, upload, verify 산출물은 `backend/data/.gitignore`에서 제외한다. 따라서 다른 기기의 새 clone이 특정 플랫폼 값을 기본으로 가지지 않는다.

Docker 재시작 시에는 작업 중이던 현재 데이터를 유지한다. 별도의 run 관리·초기화 UI는 추가하지 않았다.

## 7. 진단 모듈 영향

다음 경로는 변경하지 않았다.

```text
backend/diagnosis/modules/**
backend/screenshot/modules/**
```

진단 모듈은 이전처럼 `ctx.data_dir`, `ctx.raw_config`, `api-tree.json`, `test-accounts.json`을 사용한다. 수정된 인벤토리 계층이 진단 실행 전에 정상적인 `api-tree.json`을 제공한다.

## 8. 프런트 빌드 회복

최신 브랜치에 기존하던 JSX 닫힘 누락과 2-1 중복 선언으로 프런트 Docker 빌드가 실패하고 있었다. Base URL UI 변경을 검증할 수 있도록 다음 기존 문법 오류만 최소 수정했다.

- `frontend/src/components/DiagnosisPage.tsx`
- `frontend/src/components/diagnosis/DiagnosisReportPanel.tsx`

진단 로직이나 진단 결과 판정 로직은 변경하지 않았다.

## 9. 검증 결과

변경 대상 백엔드 테스트:

```text
26 passed
```

포함 내용:

- Base URL 역할 저장·config 동기화
- 포트와 무관한 API/Frontend 역할
- API List/URL List 파싱
- API List/OpenAPI 병합
- 소스별 Base URL 분리
- 로그인 탐색 회귀

프런트:

```text
npm run build
✓ built
```

전체 `pytest` 자동 수집은 저장소 루트의 수동 실서버 스크립트(`test_login.py`, `test_upload*.py`)가 import 시점에 `localhost:8080`으로 접속하고, 현재 로컬 Python 환경에 FastAPI가 없어 완전 수집은 중단됐다. 이는 이번 변경 대상 테스트 실패가 아니다.

## 최종 동작 예시

Base URL:

```text
http://web.example:8080  / frontend
http://api.example:3000 / api
```

입력:

```text
URL List: /login
API List: POST /api/auth/login
OpenAPI:  POST /api/auth/login + request schema
```

결과:

```text
GET  http://web.example:8080/login
POST http://api.example:3000/api/auth/login
     sources = [api_list, openapi]
```

Frontend URL에 API List가 붙거나 API URL에 URL List가 붙는 가짜 중복은 생성되지 않는다.
