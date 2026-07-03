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

- Python 3.14 이상
- 의존성: `requests`, `python-owasp-zap-v2-4`

`uv`를 사용하는 경우:

```powershell
uv sync
```

일반 pip 환경에서는:

```powershell
python -m pip install requests python-owasp-zap-v2-4
```

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

## 테스트

```powershell
python -m unittest discover -v
```

테스트는 로그인 진단, 토큰 갱신, 검색 키워드 회귀, stored SSRF 조회 선택, ZAP 컨텍스트·Swagger import 및 정책 설정을 검증합니다.

## 파일 구성

- `main.py`: CLI, 인증, 파이프라인 및 결과 병합
- `input_parser.py`: 입력과 OpenAPI 스키마 정규화
- `search_engine.py`: 의심 파라미터 정적 선별
- `payload_injector.py`: baseline 및 페이로드 검증
- `zap_engine.py`: OWASP ZAP 연동
- `role_boundary.py`: 역할별 접근 경계 검사
- `models.py`: 공통 데이터 모델
