# ARGUS

ARGUS는 OpenAPI(Swagger), URL 목록 또는 API 목록을 입력받아 SSRF와 File Inclusion 가능성을 탐색하는 보안 진단 도구입니다. 파라미터 이름과 스키마를 정적으로 선별한 뒤 자체 페이로드 검증을 수행하며, 선택적으로 OWASP ZAP Active Scan 결과를 함께 병합합니다.

허가받은 시스템에서만 사용하세요. 내부 주소 접근, 파일 경로 주입 및 시간 기반 검증 등 실제 요청을 발생시킵니다.

## 주요 기능

- OpenAPI 3.x/Swagger, URL 목록, API 목록 입력 정규화
- SSRF, LFI, RFI 의심 파라미터 탐색
- exact-match와 부분 일치 fallback을 이용한 변형 필드 탐지
- baseline 비교, 반복 타이밍, 응답 본문 및 저장 후 조회 검증
- Swagger에 선언된 동일 리소스 GET이 있을 때만 stored SSRF 재조회
- 선택적 OOB 콜백 및 OWASP ZAP 연동
- JWT, 추가 헤더, 다중 역할 토큰 및 계정 로그인 지원
- 401 응답 시 로그인 토큰 갱신 후 1회 재시도
- 결과별 `confidence`, 탐지 방식 및 요청 증거를 JSON으로 기록

## 요구 사항과 설치

- Python 3.12 이상
- 의존성: `requests`, `python-owasp-zap-v2-4`

`uv`를 사용하는 경우:

```powershell
uv sync
```

일반 pip 환경에서는:

```powershell
python -m pip install requests python-owasp-zap-v2-4
```

## 백엔드 통합

이 폴더는 독립 CLI 도구인 동시에 ARGUS 플랫폼의 정식 진단 모듈입니다. `module.py`가 내보내는 `G14Module` 인스턴스는 `diagnosis/registry.py`에 의해 자동 등록됩니다.

플랫폼 통합 실행 경로는 다음과 같습니다.

1. 프론트에서 **1-4 진단 시작**을 선택합니다.
2. 백엔드가 `G14Module.run(ctx)`를 호출합니다.
3. 모듈은 공용 인벤토리인 api-tree에서 엔드포인트를 읽어 `ScanTarget`으로 변환합니다.
4. 변환된 대상을 `precomputed_targets`로 `run_pipeline()`에 직접 주입합니다. 따라서 통합 실행은 CLI의 `--swagger` 파싱 경로를 거치지 않습니다.
5. 대시보드에 등록된 테스트 계정마다 스캔을 반복합니다. 동일한 취약점이 여러 계정에서 확인되면 한 finding으로 중복 제거하고 확인 역할을 `evidence.confirmed_by_roles`에 병합합니다.
6. 결과를 플랫폼 표준 `SectionReport`로 변환해 `data/report/1-4/latest.yaml`에 저장합니다.

## 기본 사용법

두 Swagger 파일을 함께 읽고 자체 인젝터만 실행하는 예시입니다. 여러 Swagger 경로는 쉼표 또는 세미콜론으로 구분합니다.

```powershell
python main.py `
  --swagger "swagger_8080.json,swagger_8081.json" `
  --output findings.json `
  --no-zap
```

ZAP daemon이 실행 중이라면 `--no-zap`을 빼고 연결 정보를 지정할 수 있습니다.

```powershell
python main.py --swagger swagger_8080.json `
  --zap-api-url http://127.0.0.1:8090 `
  --zap-api-key YOUR_KEY `
  --output findings.json
```

전체 옵션은 다음 명령으로 확인합니다.

```powershell
python main.py --help
```

## 인증 스캔

계정 목록은 JSON 배열로 전달합니다. 셸의 JSON 인용 규칙에 주의하세요.

```powershell
$credentials = '[{"email":"admin@example.com","password":"secret"}]'
python main.py `
  --swagger "swagger_8080.json,swagger_8081.json" `
  --credentials $credentials `
  --login-url http://127.0.0.1:8081/api/v1/login `
  --output findings.json `
  --no-zap
```

로그인 성공 시 `[로그인 성공]` 메시지가 출력됩니다. 모든 계정이 실패하면 익명 스캔으로 전환하지 않고 `[스캔 중단]`을 출력하며 결과 파일을 만들지 않습니다.

이미 발급된 토큰은 `--jwt-token` 또는 반복 가능한 `--token-set ROLE=JWT`로 전달할 수 있습니다. 추가 인증 헤더는 `--auth-header "X-Api-Key: value"`를 사용합니다.

## OOB 검증

블라인드 SSRF는 실제 콜백 수신이 가장 강한 증거입니다.

```powershell
python main.py --swagger swagger_8080.json `
  --oob-enabled --oob-domain example.oast.fun `
  --output findings.json
```

현재 기본 OOB provider는 연동 지점만 제공하므로, 실제 콜백 서비스의 등록·polling 구현 또는 별도 provider 연결이 필요합니다.

## 결과

JSON 결과에는 전체 Swagger 대상 수, 검색 hit, 인증/기준 요청으로 인해 건너뛴 대상, 자체 인젝터 및 ZAP 결과, 병합된 finding이 포함됩니다. 주요 finding 필드는 다음과 같습니다.

- `confidence`: `HIGH`, `MEDIUM`, `LOW`
- `detection_method`: `IN_BAND`, `REPEATED_TIMING`, `BASELINE_DIFF`, `OOB` 등
- `evidence`: 판정 근거
- `stored_ssrf_probe`: 별도 GET 검증 결과. 적합한 조회 엔드포인트가 없으면 `null`

실행 방식에 따라 저장 경로가 다릅니다.

- CLI 단독 실행: `--output`으로 지정한 JSON 파일. 예: `findings.json`
- 백엔드 통합 실행 원본: `backend/diagnosis/modules/1-4/_last_run.{ROLE}.json`. 예: `_last_run.USER.json`, `_last_run.SELLER.json`. 역할별 감사 로그이며 `.gitignore`에 의해 Git에는 포함되지 않습니다.
- 백엔드 통합 최종 리포트: `data/report/1-4/latest.yaml` (`backend/data/report/1-4/latest.yaml`)

## 테스트

```powershell
python -m unittest discover -v
```

테스트는 로그인 진단, 토큰 갱신, 검색 키워드 회귀, stored SSRF 조회 선택, ZAP 컨텍스트·Swagger import 및 정책 설정을 검증합니다.

## 파일 구성

| 그룹 | 파일 | 역할 |
|---|---|---|
| 엔진 핵심 | `main.py` | CLI 진입점 및 `run_pipeline()` 핵심 파이프라인 |
| 엔진 핵심 | `input_parser.py` | Swagger/URL 목록/API 목록을 `ScanTarget`으로 정규화 |
| 엔진 핵심 | `search_engine.py` | SSRF/LFI 의심 파라미터 정적 탐색 |
| 엔진 핵심 | `payload_injector.py` | baseline 비교, 페이로드 주입 및 검증 |
| 엔진 핵심 | `zap_engine.py` | OWASP ZAP Active Scan 연동 |
| 엔진 핵심 | `role_boundary.py` | 역할별 접근 경계(401/403) 검사 |
| 엔진 핵심 | `models.py` | `ScanTarget`, `ScanParam` 등 공통 데이터 모델 |
| 백엔드 통합 | `module.py` | 진단 모듈 레지스트리 진입점 (`G14Module`) |
| 백엔드 통합 | `manifest.yaml` | 모듈 메타데이터(id/title/chapter 등) |
| 백엔드 통합 | `inventory_bridge.py` | api-tree `Endpoint`를 `ScanTarget`으로 변환 |
| 백엔드 통합 | `report_mapper.py` | 엔진 결과를 `DiagnosisFinding`으로 변환 |
| 테스트 | `test_main.py` | CLI 인증 및 실행 흐름 테스트 |
| 테스트 | `test_search_engine.py` | 정적 탐색 회귀 테스트 |
| 테스트 | `test_payload_injector.py` | baseline, 인증 갱신 및 주입 검증 테스트 |
| 테스트 | `test_zap_engine.py` | ZAP 컨텍스트, import 및 정책 테스트 |
| 테스트 | `test_report_mapper.py` | 역할별 결과 중복 제거 및 리포트 매핑 테스트 |
| 설정 파일 | `pyproject.toml` | 의존성 및 Python 버전 명시 |
| 설정 파일 | `uv.lock` | `uv` 의존성 잠금 파일 |
| 설정 파일 | `.python-version` | 로컬 Python 버전 힌트 |
| 설정 파일 | `.gitignore` | 실행 결과와 로컬 산출물 제외 규칙 |
