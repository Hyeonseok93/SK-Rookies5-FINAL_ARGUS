# 1-5 리플렉티드(Reflected) 진단 수정 기록

세션 진행 내용 요약. 날짜: 2026-07-07.

## 배경 / 최초 문제

`1-5 검증되지 않은 리다이렉트와 포워드` 진단 중 "리플렉티드" 부분(META_REFRESH/JS_REDIRECT/
REFLECTED_VALUE/LOCATION_HEADER 탐지)이:
- 진단하는 데 시간이 매우 오래 걸림
- 결과로는 하나도 안 잡힘 (findings 0건)

## 작업 범위 제약 (사용자 지시)

> 내가 추가한 리플렉티드 코드만 수정하고 이전에 있던 리다이렉트 취약점 코드는 수정하지 마.

- **수정 가능**: `reflected_bridge.py`, `reflected_detector.py`, `reflected_browser_verify.py`,
  `reflected_candidates.py`, `reflected_engine.py`, `reflected_models.py`, `reflected_payloads.py`
  (전부 git에 커밋되지 않은 신규 파일 — 사용자가 직접 추가)
- **수정 금지(원래는)**: `scanner.py`, `probes.py`, `targets.py`, `redirect_rules.py`
  (pre-existing, 이 세션 시작 전부터 uncommitted 변경 있었음 — 내가 만든 변경 아님)
- 이후 근본 원인이 `targets.py`/`scanner.py`에 있는 것으로 확인되어, 사용자에게
  `AskUserQuestion`으로 승인을 받은 뒤 두 파일도 함께 수정함 (아래 "수정 4" 참고).

## 수정 1 — LOCATION_HEADER 탐지 결과를 버리던 필터 제거 (0건 문제의 핵심 원인)

**파일**: `reflected_bridge.py`

`_SKIP_DETECTION_TYPES = frozenset({"LOCATION_HEADER"})` 로 `run_on_jobs()`가
`LOCATION_HEADER` 탐지 결과를 전부 버리고 있었음. 근거였던 가정("이미 sink 토큰 방식이
Location 헤더 open redirect를 다 잡아준다")이 틀렸음 —
`reflected_payloads.py`의 페이로드는 화이트리스트 **우회 전용**(`//host`, `/\host`,
`https:host`, 서브도메인 위장, `@` userinfo 등)인데, sink 방식은 고정 URL 하나만
테스트하므로 이 우회 페이로드들이 유발하는 Location 헤더 반영은 sink 방식으로
원리적으로 못 잡음. 즉 13개 우회 페이로드를 다 쏴놓고 그 결과(LOCATION_HEADER)만
버리는 구조였음.

**조치**: 필터 제거. 이제 LOCATION_HEADER/META_REFRESH/JS_REDIRECT/REFLECTED_VALUE
네 가지 전부 finding으로 반환.

**검증**: 가짜 서버(`//host`는 막고 `https://`만 막는 얕은 화이트리스트)로 스모크 테스트 →
수정 전 0건 → 수정 후 HIGH severity finding 정상 탐지 확인.

## 수정 2 — 성능 (순차 요청 → 병렬 처리 + 커넥션 재사용)

**문제**: job 1개당 baseline 1회 + 페이로드 최대 13회 = 최대 14회 요청. job이 최대
~1200개(phase A 400 + phase B 800, config 상한)까지 생겨 순차 실행 시 최대
~16,800회의 블로킹 요청. 게다가 `requests.request()`를 매번 새로 호출해 매 요청마다
새 TCP/TLS 커넥션을 맺음 (연결 재사용 없음).

**조치**:
- `reflected_detector.py`: 스레드별 `requests.Session()` 재사용 (connection pooling)
  — `threading.local()`로 스레드 세이프하게 구현
- `reflected_bridge.py`의 `run_on_jobs()`: 순차 for-loop → `ThreadPoolExecutor`
  (workers=16)로 병렬화

**검증**: 실측 180개 job(리다이렉트/CORS 대상 API 샘플)에 대해 reflected 단계
5.4초 소요 (기존 순차 방식이었다면 최소 수십 배 더 걸렸을 것).

## 수정 3 — 헤드리스 브라우저 검증 단계 최적화 + 회귀 버그

**파일**: `reflected_browser_verify.py`

**최적화**: 로그인/인증 문맥 후보마다 Chromium을 매번 새로 launch하던 것을
전체 후보에 대해 1회만 launch하도록 변경. `wait_until="networkidle"`
(SPA는 웹소켓/폴링 때문에 도달 안 해서 매 후보 15초 풀타임아웃 소모) →
`"domcontentloaded"` + 짧은 고정 대기(1초)로 변경, 타임아웃 15s→8s.

**회귀 버그 (직접 발견/수정)**: 브라우저를 1회만 launch하도록 리팩터링하면서
`sync_playwright()`/`chromium.launch()` 호출이 try/except 밖으로 나가버림.
원래는 후보마다 개별적으로 감싸져 있어 브라우저 실행 실패(바이너리 미설치, 워커
스레드에서 실행되어 생기는 시그널 등록 실패 등)가 조용히 무시됐는데, 리팩터링 후
이 실패가 `scanner.py`의 `run_g15_scan()`까지 예외로 전파되어 **그 뒤에 실행되는
CORS/crossdomain 검사까지 통째로 중단**되는 문제 발생 ("CORS가 갑자기 사라짐"
증상의 원인 중 하나). `try/except`로 전체 브라우저 블록을 다시 감싸서 해결.

## 수정 4 — reflected_bridge.py 공개 함수 전부에 방어적 예외 처리 추가

**파일**: `reflected_bridge.py`

`scanner.py`(수정 대상 아님)는 `count_login_redirect_candidates()` /
`run_on_jobs()` / `run_login_redirect_browser_check()` 호출을 try/except로
감싸지 않음. 즉 리플렉티드 코드 내부에서 예외가 하나라도 새어나가면 그 뒤에
이어지는 리다이렉트/CORS/crossdomain 검사까지 전부 중단됨. `scanner.py`를 고칠 수
없으므로, 대신 이 세 함수 전부가 **어떤 경우에도 예외를 밖으로 던지지 않고**
안전한 기본값(빈 리스트/0)으로 대체하도록 방어적으로 감쌈.

**검증**: 정상 탐지 동작 유지 확인 + 일부러 깨진 입력을 줘서 예외 없이 빈 결과로
넘어가는 것 확인.

## 발견 1 (별개 원인) — CORS가 다시 사라진 이유: 스캔 대상 목록 문제

`probes.run_cors_probes()`가 도는 대상(`bases`)은 `config.yaml`의 `targets:`가 아니라
`diagnosis/replay/normalize.py`의 `collect_probe_base_urls()`를 거치는데, **대시보드에
저장된 base URL이 하나라도 있으면 config.yaml의 targets는 통째로 무시**하고 대시보드
목록만 씀. 그런데 `data/base-urls.json`(대시보드 저장값)에는:

```json
{"urls": [{"url": "http://192.168.0.23"}, {"url": "http://192.168.0.23:8080"}]}
```

`http://192.168.0.23:8081`(admin-api)이 빠져 있었음 → 그동안 CORS 검사가 admin-api를
아예 스캔 대상에서 빼먹고 있었음 (취약점이 고쳐진 게 아니라 대상에서 빠진 것).

**조치**: `data/base-urls.json`에 `http://192.168.0.23:8081` 항목 추가.
**검증**: `resolved_base_url_strings()` / `collect_probe_base_urls(None)` 모두 3개
base URL 반환 확인. 이후 실제 스캔에서 CORS 정상 복귀 확인됨 (사용자 확인).

이 파일(`diagnosis/replay/normalize.py`, `data/base-urls.json`)은 1-5 모듈도
리플렉티드 코드도 아닌 공용 인프라라 범위 밖이었지만, `AskUserQuestion`으로
"대시보드에 8081 추가" 승인받고 진행함.

## 발견 2 (별개 원인) — 리플렉티드가 여전히 0건인 이유: 프로브 요청에 인증이 전혀 없었음

CORS 복구 후에도 리플렉티드는 계속 0건. 실제 대상 서버(`192.168.0.23`)에 직접
요청을 보내 확인한 결과:

```
A month  -> 500  (서버 내부 오류)
A date   -> 401  {"error":{"code":"AUTH-001" ...}}   ← 인증 필요
A userId -> 401  {"error":{"code":"AUTH-001" ...}}   ← 인증 필요
B redirect  -> 500
B returnUrl -> 500
```

**원인**: `targets.py`의 `build_phase_a_jobs()` / `build_phase_b_jobs()`가 프로브
요청을 만들 때 로그인 세션(`account_auth`)을 전혀 넘기지 않음. 즉 페이로드가
인증이 필요한 컨트롤러 로직(리다이렉트/반사가 실제로 일어날 수 있는 지점)에
도달하기도 전에 401로 차단당함 — **리플렉티드 검사뿐 아니라 원래 있던 sink 기반
open-redirect 검사(`probes.run_redirect_jobs`)도 인증 필요 엔드포인트(전체 438개
중 대다수)에서는 애초에 아무것도 못 잡는 구조**였음.

이건 `targets.py`/`scanner.py`(pre-existing, 원래 수정 금지 범위) 안의 코드라
`AskUserQuestion`으로 승인받고 진행:

- `targets.py`
  - `build_phase_a_jobs()`에 `account_auth` 파라미터 추가, `build_probe_request(..., account_auth=account_auth)`로 전달 (이 함수는 이미 `account_auth`를 지원하고 있었음 — `targets.py`가 안 쓰고 있었을 뿐)
  - `build_phase_b_jobs()`는 `build_probe_request`를 거치지 않고 헤더를 직접 만들므로, `inventory.auth_util.auth_headers(account_auth)`로 동일한 인증 헤더를 수동 추가
- `scanner.py`
  - phase A/B job 생성 **전**에 `auth_session = _primary_auth(raw, data_dir=ctx.data_dir)`을 미리 조회해서 두 빌더 함수에 `account_auth=auth_session`으로 전달
  - 이후 브라우저 쿠키 검증부에서 같은 세션을 재사용하도록 중복 로그인 호출 제거

**검증**: 실제 대상에 재요청 → `401`(미인증)이 `403`(권한 부족, 로그인은 됐지만
role 권한 없음)으로 바뀜 — 인증이 정상적으로 붙는 것 확인.

## 현재 상태 (2026-07-07 기준)

- 성능: 180개 job 기준 reflected 단계 ~5.4초 (병렬화 이전 대비 대폭 개선)
- CORS: 정상 탐지 복귀 확인됨 (사용자 확인)
- 리플렉티드: 인증까지 붙인 뒤에도 실측 샘플(180개, calendar/settlements/members/posts/comments
  + 24종 speculative redirect 파라미터명)에서는 **여전히 0건**
  - 이 API가 순수 JSON REST 백엔드라, 페이지 리다이렉트(Location 헤더 기반) 자체가
    거의 없는 구조일 가능성이 높음 — 이 경우 0건이 정확한 "이상 없음" 결과일 수 있음
  - 다만 한 가지 커버리지 공백을 추가로 발견함: 현재 로드된 api-tree에는
    `http://192.168.0.23`(포트 없는 프런트엔드) base_url을 가진 엔드포인트가
    **0개**임 (`8080`: 226개, `8081`: 212개만 존재). config.yaml에는
    `include_frontend_routes: true`로 되어 있는데도 실제로는 프런트엔드 라우트가
    인벤토리에 하나도 없음 — 만약 실제 취약점이 프런트엔드 SPA의 로그인 페이지
    클라이언트 사이드 리다이렉트(`?returnUrl=` 등)라면, 애초에 이 엔드포인트가
    인벤토리에 없어서 phase A/B job 자체가 안 만들어지고, 따라서
    `run_login_redirect_browser_check`(헤드리스 브라우저 검증)도 절대 그 페이지를
    테스트할 수 없는 구조임
  - 참고로 `probe_mode=full`로 전체 인벤토리(9,274 job)를 대상으로 계산했을 때
    로그인/인증 문맥 브라우저 검증 후보(`login_candidate_count`)는 665건 확인됨 —
    다만 이건 전부 `8080`/`8081` API 경로 중 URL에 `login`/`auth`가 포함된
    것들이고, 실제 프런트엔드 페이지는 아님

## 다음에 확인해볼 것 (미해결)

1. `include_frontend_routes: true`인데도 api-tree에 프런트엔드(`192.168.0.23`,
   포트 없음) 라우트가 0개인 이유 — `inventory/` 쪽 markdown 파싱 또는 인벤토리
   재생성(스캔 전 "Verify"/inventory 갱신 필요 여부) 확인 필요. 이건 1-5 모듈도
   아니고 리플렉티드 코드도 아닌 별개 서브시스템이라 아직 손대지 않음.
2. 위 문제를 해결해 프런트엔드 로그인 페이지가 인벤토리에 잡히면, 리플렉티드
   진단(특히 헤드리스 브라우저 검증)이 실제로 뭔가를 잡아낼 가능성이 있음 —
   현재 0건이 "진짜 이상 없음"인지 "커버리지 공백으로 인한 미탐"인지는 그 이후에
   더 명확해짐.

## 수정된 파일 목록

| 파일 | 종류 | 비고 |
|---|---|---|
| `reflected_bridge.py` | 신규(사용자 추가) | LOCATION_HEADER 필터 제거, 병렬화, 방어적 예외 처리 |
| `reflected_detector.py` | 신규(사용자 추가) | Session 재사용 |
| `reflected_browser_verify.py` | 신규(사용자 추가) | 브라우저 1회 launch, networkidle→domcontentloaded, 회귀 버그 수정 |
| `targets.py` | pre-existing | 사용자 승인 후 수정 — `account_auth` 파라미터 추가 |
| `scanner.py` | pre-existing | 사용자 승인 후 수정 — auth_session을 job 생성 전에 조회해 전달 |
| `data/base-urls.json` | 런타임 데이터(gitignore) | 사용자 승인 후 수정 — admin-api(8081) 추가 |
