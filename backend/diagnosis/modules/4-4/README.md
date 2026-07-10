# 진단 모듈 4-4 — 비인증 상태로 중요 페이지 접근 가능성

## 개요

4-4 모듈은 로그인 후에만 사용할 수 있어야 하는 중요 페이지를 비인증 상태로 요청하고, 보호 콘텐츠가 노출되는지 능동적으로 검사한다.

관리자 페이지, 마이페이지, 회원·주문·결제 페이지처럼 인증이 필요한 경로가 URL 직접 입력만으로 열리는 경우를 탐지한다. HTTP 요청은 `httpx` 기반 공용 전송 계층을 사용한다.

## 진단 흐름

1. `api-tree`를 읽고 대시보드 Base URL 및 추가 Base URL 범위로 엔드포인트를 제한한다.
2. 경로, 인증 라벨, 인증 헤더를 기준으로 중요 페이지 후보를 선정한다.
3. 기본 강제 탐색 경로와 사용자 지정 경로를 후보에 추가한다.
4. 각 후보를 익명 클라이언트와 인증 클라이언트로 각각 요청한다.
5. 익명 응답의 로그인 차단 여부, 상태 코드, 본문 지문, SPA 셸 여부를 분석한다.
6. 같은 origin의 다른 후보에서 익명 `401/403`이 관측됐는지 확인하여 서버의 인증 강제 여부를 판단한다.
7. HIGH/MEDIUM 결과에는 익명·인증 응답 비교 리플레이 증거를 기록한다.

익명 요청과 인증 요청은 서로 다른 `HttpxTransport` 인스턴스를 사용한다. 따라서 인증 응답에서 저장된 쿠키가 익명 요청으로 전달되지 않는다.

## 후보 선정

기본 후보 점수는 다음과 같다.

| 신호 | 점수 |
|---|---:|
| 중요 경로 키워드 포함 | +2 |
| `auth == ["authenticated"]` | +3 |
| `auth`에 `authenticated` 포함 | +2 |
| 명시적 토큰 인증 헤더 포함 | +2 |

기본 `min_score`는 `2`이다.

중요 경로 키워드는 다음 범주를 포함한다.

```text
admin, master, manager, manage, console, backoffice, cms,
mypage, dashboard, board, 게시판, post, notice, write,
account, member, seller, user, profile, settings, config,
order, payment, checkout, upload, internal, private
```

명시적 토큰 인증 헤더는 다음과 같다.

```text
Authorization, X-API-Key, X-Auth-Token, X-Access-Token
```

`Cookie` 헤더는 보호 신호로 사용하지 않는다. 브라우저는 공개 엔드포인트에도 동일 출처 쿠키를 자동 첨부할 수 있기 때문이다.

다음 대상은 기본적으로 제외한다.

- 로그인, 회원가입, 로그아웃 및 `/api/auth/*`
- health, actuator, public, swagger 경로
- CSS, JavaScript, 이미지, 폰트 등 정적 리소스
- `include_frontend=false`일 때의 프런트엔드 엔드포인트
- 기본 설정에서 GET, HEAD, OPTIONS가 아닌 메서드

## 강제 탐색

[`assets/forced_browse_paths.txt`](assets/forced_browse_paths.txt)의 경로를 각 Base URL에 결합하여 GET 후보로 추가한다.

기본 경로는 다음과 같다.

```text
/admin
/admin/users
/manage
/board/write
/mypage
/dashboard
/account
/profile
```

`extra_protected_paths` 설정으로 프로젝트별 경로를 추가할 수 있다.

## 판정 기준

### 정상 차단

다음 응답은 정상적인 인증 차단으로 보고 finding을 생성하지 않는다.

- 익명 응답이 `401` 또는 `403`
- 익명 응답이 로그인, signin, auth, SSO 경로로 리다이렉트됨
- 익명 응답 본문에서 비밀번호 필드 또는 로그인 화면 마커가 발견됨
- 응답이 `404`, `405`, `5xx`이거나 성공 응답이 아님

### 취약 또는 검토 대상

| Trigger | 조건 | 심각도 |
|---|---|---|
| `anon_ok_auth_denied` | 익명 요청은 2xx지만 유효한 인증 요청은 401/403 | HIGH |
| `unauth_access_confirmed` | 보호 신호가 있는 페이지가 익명과 인증 상태에서 모두 2xx | origin baseline에 따라 HIGH 또는 MEDIUM |
| `unauth_access_no_account` | 보호 신호가 있는 페이지가 익명 2xx이며 비교 계정이 없음 | origin baseline에 따라 HIGH 또는 MEDIUM |
| `client_side_guard_only` | 익명 응답이 공개 SPA 루트 셸과 동일하고 보호 데이터 마커가 없음 | INFO |

같은 origin의 후보 중 하나라도 익명 요청에 `401/403`을 반환하면 해당 origin은 인증을 강제하는 것으로 간주한다. 이 origin에서 다른 보호 후보가 익명 `2xx`를 반환하면 인증 누락 가능성이 높으므로 HIGH로 판정한다. 해당 baseline이 없으면 공개 API일 가능성을 고려하여 MEDIUM으로 판정한다.

경로·인증 라벨·토큰 헤더 등 보호 신호가 없는 공개 엔드포인트는 익명과 인증 응답이 같더라도 4-4 취약점으로 판정하지 않는다.

## SPA 오탐 방지

프런트엔드 후보를 검사할 때 같은 Base URL의 `/` 응답 지문을 함께 수집한다.

후보의 익명 응답이 공개 루트 SPA 셸과 동일하고 관리자·회원·계정·주문·결제 등의 보호 데이터 마커가 없으면 서버 측 보호 콘텐츠 노출로 확정하지 않고 `client_side_guard_only` INFO로 기록한다.

실제 데이터 접근 통제 여부는 해당 화면이 호출하는 백엔드 API 후보에서 판정한다.

## 설정

설정 키는 `diagnosis_4_4`이다. 모든 항목은 선택 사항이다.

```yaml
diagnosis_4_4:
  min_score: 2
  max_candidates: 80
  scan_all_inventory: false
  forced_browse_enabled: true
  include_frontend: true
  include_write_methods: false
  extra_protected_paths:
    - /seller/dashboard
    - /internal/reports
  extra_base_urls:
    - https://admin.example.com
```

| 설정 | 기본값 | 설명 |
|---|---:|---|
| `min_score` | `2` | 후보로 선택할 최소 점수 |
| `max_candidates` | `80` | 최대 후보 수. `scan_all_inventory=true`이면 제한하지 않음 |
| `scan_all_inventory` | `false` | 점수 필터 없이 허용된 전체 인벤토리를 검사 |
| `forced_browse_enabled` | `true` | 기본 및 추가 보호 경로를 강제 탐색 후보로 추가 |
| `include_frontend` | `true` | 프런트엔드 엔드포인트 포함 여부 |
| `include_write_methods` | `false` | POST, PUT, PATCH, DELETE 등 쓰기 메서드 포함 여부 |
| `extra_protected_paths` | `[]` | 추가로 검사할 중요 경로 |
| `extra_base_urls` | `[]` | 기본 진단 범위에 추가할 Base URL |

`include_write_methods=true`는 서버 데이터를 변경하는 요청을 실행할 수 있으므로 안전성이 확인된 환경에서만 사용해야 한다.

## 결과 상태

| 상태 | 의미 |
|---|---|
| `fail` | HIGH finding이 한 건 이상 존재 |
| `warn` | HIGH는 없고 MEDIUM finding이 존재 |
| `pass` | 후보를 검사했으나 HIGH/MEDIUM finding이 없음 |
| `no_targets` | 중요 페이지 후보가 없음 |
| `skipped` | 대시보드 Base URL 범위에 해당하는 엔드포인트가 없음 |
| `error` | api-tree가 없거나 비어 있음 |

통계는 INFO finding인 `4-4 진단 통계`로 보고서 첫 번째 항목에 삽입된다.

## 증거와 리플레이

finding의 `rule_id`는 `4-4-unauth-page-access`이다. 주요 evidence는 다음과 같다.

- 엔드포인트 ID, 메서드, 경로, Base URL
- 익명·인증 HTTP 상태 코드
- 익명·인증 본문 SHA-256 및 크기
- 응답 Content-Type과 본문 일부
- 로그인 게이트 여부와 Location 헤더
- 보호 신호 및 origin 인증 강제 여부
- 관련 진단 항목: `4-4`, `3-4`, `4-3`

HIGH/MEDIUM finding은 섹션 evidence 디렉터리에 익명 요청과 인증 요청을 기록한다. 인증 세션이 있으면 두 응답의 비교 단계도 함께 저장한다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `manifest.yaml` | 모듈 메타데이터와 엔진 선언 |
| `module.py` | 레지스트리 진입점, `SectionReport` 생성 및 저장 |
| `scanner.py` | 전체 진단 흐름, 설정 처리, 상태 집계 |
| `targets.py` | api-tree, Base URL 범위, 로그인 리포트 로드 |
| `candidates.py` | 후보 점수, 보호 신호, 제외 및 강제 탐색 규칙 |
| `probes.py` | 익명/인증 프로브, origin baseline, finding과 리플레이 생성 |
| `page_rules.py` | 로그인 게이트, SPA 및 취약 응답 판정 순수 함수 |
| `transport.py` | 공용 `HttpxTransport`, `ProbeResponse` 재노출 |
| `assets/forced_browse_paths.txt` | 기본 강제 탐색 경로 목록 |

## 실행 전 준비 사항

- `backend/data` 아래에 유효한 api-tree가 있어야 한다.
- 인증 비교를 사용하려면 Argus 테스트 계정과 로그인 설정이 구성되어야 한다.
- 대시보드 Base URL 또는 설정의 target/Base URL이 실제 검사 대상 origin과 일치해야 한다.
- 능동 진단이므로 운영 환경보다 별도의 허가된 테스트 환경에서 실행하는 것이 안전하다.
