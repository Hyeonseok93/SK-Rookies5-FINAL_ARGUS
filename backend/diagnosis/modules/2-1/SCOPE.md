# 2-1 악성코드파일 업로드 — 스코프

KISA Web/API 개발보안 Guideline **2-1**. 사용자·판매자 파일 업로드 API를 대상으로
① 허용되지 않은 확장자 차단 여부, ② 업로드 경로/주소의 불필요한 노출 여부를 점검한다.

원 가이드의 세 번째 항목(업로드 파일의 실행 권한 제한 — 파일시스템 실행 비트)은 HTTP
블랙박스 진단으로는 관측이 불가능한 영역이라 **범위에서 제외**했다. 시도했던 대안(재요청
응답에서 실행 여부를 추론하는 marker-echo 휴리스틱)도 신뢰도가 낮아 제거했다 — 자세한
논의는 대화 로그 참고, 필요 시 OOB 콜백 기반 능동 확인 등 별도 채널을 추가하는 방향으로
재검토 가능.

2-2(다운로드/traversal)·1-4(SSRF/LFI)와 겹칠 수 있음 — 필요 시 `related_sections`로 표기.

## 대상 엔드포인트 선정

| 우선순위 | 소스 | 동작 |
|---|---|---|
| 1 | `config.yaml`의 `diagnosis_2_1.upload_endpoints` | **명시된 엔드포인트만** 테스트 (그 외 자동탐지 결과는 섞지 않음) |
| 2 | api-tree 자동탐지 (`targets.py::discover_upload_endpoints`) | `Content-Type: multipart/form-data` 또는 `image/file/photo/thumbnail/...` 계열 body 파라미터를 가진 POST/PUT |

파일 필드 외에 필요한 다른 필드(예: `sellerId`, `memberId`, `title` 등)는 **하드코딩하지 않고**
api-tree에 기록된 `sample` 값(어택 서피스 빌드 시 수집됨)으로 채우거나, 없으면 타입별 기본값을
채운다. 특정 비즈니스 필드를 강제로 지정해야 하면 `upload_endpoints[].extra_fields`로 오버라이드한다.

## 확장자 정책 (동적)

`assets/dangerous-extensions.yaml`에서 로드. 이미지에 한정하지 않고, 파일만 편집하면
새 위험 확장자를 코드 변경 없이 추가할 수 있다.

- `allowed_extensions_default`: 정책을 모를 때 쓰는 기본 화이트리스트 (엔드포인트별로
  `upload_endpoints[].allowed_extensions`로 override 가능)
- `disallowed_extensions`: 화이트리스트에 없어야 하는 위험 확장자 후보. 항목당 다음 우회
  기법을 모두 시도한다 (`payloads.py`):
  - `direct_extension` — 확장자 그대로
  - `content_type_spoof` — `Content-Type: image/png`로 위장
  - `magic_byte_polyglot` — PNG magic byte + 스크립트 본문
  - `double_extension` / `double_extension_reverse` — `shell.php.png` / `shell.png.php`
  - `null_byte` — `shell.php\0.png`
  - `case_bypass` — `shell.PHP`
  - `trailing_dot` — `shell.php.`

判定(`rules.classify_extension_bypass`): 응답이 2xx이고 실패 마커(`success:false`, `error` 등)가
없으면 **차단되지 않음(high)**. Baseline(정상 이미지)이 거부되면 info로 별도 표시 — 다른 결과를
해석할 때 "필터가 너무 엄격해서 baseline도 막혔는지"를 구분하기 위함.

## 경로/주소 노출 [조건 2]

모든 업로드 응답의 **본문**과 **헤더**에서 다음을 정규식으로 탐지 (`rules.detect_path_exposure`):

| 패턴 | severity |
|---|---|
| Windows 절대경로 (`C:\...`) | medium |
| Unix 절대경로 (`/var/...`, `/home/...` 등) | medium |
| Java 스택트레이스 | medium (본문만) |
| 내부 IP/호스트 (`10.x`, `192.168.x`, `localhost`, `host.docker.internal`) | low |

헤더는 이름이 `url`/`path`/`location`/`filepath`/`key`/`storagepath`로 끝나는 것만 검사한다
(`Location`, `X-File-Path` 등). CORS `Access-Control-Allow-Origin` 같은 흔한 헤더까지 다 뒤지면
개발용 localhost 오리진 하나로 모든 요청이 오탐 나기 때문 — 본문 JSON 키 필터링과 동일한 기준.

정상적인 공개 CDN URL은 대상이 아니며, **서버 내부 파일시스템 경로/사설 주소**만 이슈로 잡는다.

## ZAP 연동

`diagnosis_2_1.zap_enabled: true`일 때 httpx 페이즈와 **완전히 동일한** 페이로드 매트릭스를
ZAP(`zap.core.sendRequest`)로 한 번 더 보낸다 (`zap_scan.py` / `transport.py`).

- 인증 헤더는 요청마다 직접 붙인다 (httpx 페이즈와 동일) — ZAP Replacer는 필요 없음.
  Replacer는 ZAP이 자체적으로 만드는 스파이더/액티브스캔 요청에만 필요하고, 우리가 이미
  완성된 raw HTTP 요청을 `sendRequest`로 보낼 때는 해당 없음.
- 모든 프로브가 `sendRequest`를 통해 나가므로 ZAP Sites/History에 기록되고, 일반 프록시
  트래픽처럼 **ZAP 패시브 스캐너가 자동으로 실행**된다. 응답을 기다린 뒤
  (`zap_passive_wait_seconds`, 기본 60초) 우리가 보낸 URL에 한정해서 알림을 수집한다
  (`zap_scan.collect_supplemental_findings` — 사이트 전체가 아니라 이번 스캔에서 실제로
  건드린 URL만).
- 대표적으로 잡히는 supplemental 패시브 규칙: `10021`(X-Content-Type-Options 누락),
  `0`/`10033`(Directory Browsing), `40035`(Hidden File Finder), `10096`(Timestamp Disclosure).
  고정 화이트리스트가 아니라 **우리가 보낸 URL에서 관측된 알림은 전부** 넘어오며,
  `PLUGIN_LABELS`는 표시용 라벨일 뿐 필터가 아니다.
- ZAP이 꺼져 있거나 `ensure_zap_proxy`가 실패하면 `ZapNotAvailableError`를 잡아
  httpx 결과만으로 계속 진행하고, 최종 message에 "ZAP skipped/unavailable"을 덧붙인다
  (2-2와 동일한 degrade 방식).
- 매 실행은 `reset_zap_workspace`로 시작/종료 시 세션을 초기화해, 이전 2-2/7-2 실행의
  alert가 2-1 결과에 섞이지 않게 한다.

## config

```yaml
diagnosis_2_1:
  timeout: 15
  max_targets: 20
  httpx_enabled: true
  zap_enabled: false            # true로 켜면 위 ZAP 연동 페이즈가 추가로 실행됨
  zap_passive_wait_seconds: 60
  allowed_extensions: [jpg, jpeg, png, gif, webp]   # endpoint 별 override 없을 때 기본값
  upload_endpoints:                                  # 지정 시 이 목록만 테스트
    - method: POST
      path: /api/v1/posts
      file_field: images
      allowed_extensions: [jpg, jpeg, png, gif, webp]
      extra_fields:
        content: "argus-test"
        memberId: "1"
        title: "argus-test"
        type: "REVIEW"
    - method: POST
      path: /api/v1/seller/accommodations
      file_field: thumbnail
      extra_fields:
        name: "argus-test"
        category: "HOTEL"
        location: "seoul"

zap:
  proxy: "http://127.0.0.1:8090"   # config.yaml 공용 zap 섹션 (다른 모듈과 동일)
  api_key: ""
```

## Not in scope

- Path traversal on download/export params (→ **2-2**)
- SSRF via file URL fetch (→ **1-4**)
- 업로드 파일의 실행 권한 제한(파일시스템 실행 비트) — HTTP 블랙박스 진단으로 관측 불가능해
  범위에서 완전히 제외. 실무에서는 서버 설정/파일시스템을 직접 점검해야 함.
