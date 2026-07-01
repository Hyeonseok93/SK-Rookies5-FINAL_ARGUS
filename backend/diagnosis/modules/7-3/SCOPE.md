# 7-3 모듈 스코프 — 서버 헤더정보 노출

KISA Web/API Guideline **7-3** (PDF p.142–148).  
OWASP WSTG **CONFIG-02**와 동일 축.

## 점검 목표

HTTP **응답 헤더**에 웹/API **서버·스택·버전·환경** 정보 노출 여부.  
응답 body(500 stack trace 등)는 **6-1** — 본 모듈 범위 아님.

## strict 모드 (기본 `true`)

| 기능 | 설명 |
|------|------|
| **고정 헤더 25종** | KISA + OWASP + ZAP passive 대표 헤더 |
| **이름 휴리스틱** | `X-Custom-Version`, `X-App-Backend` 등 `version`/`powered`/`aspnet`… 포함 이름도 점검 |
| **severity 상향** | strict 시 제품명만·환경명·기타 스택 힌트도 **medium** (기본 low → fail) |
| **환경명** | `X-Environment: staging` 등 |
| **제품 사전 확대** | Kestrel, Fastify, Django, Laravel, Vite, Traefik 등 50+ |

### config.yaml

```yaml
diagnosis_7_3:
  strict: true
  probe_mode: base_only   # base_only | sample | full
  sample_size: 20         # sample 모드: base당 path 수
  include_cdn_headers: false
  extra_probe_paths: []
  timeout: 8
```

## Probe 범위 (3단계)

| 모드 | 동작 |
|------|------|
| **base_only** | Base URL × `/` (+ 추가 경로) |
| **sample** | 위 + api-tree에서 base당 N path |
| **full** | api-tree 매칭 path 전부 probe |

동일 `(base_url, header, value)` → finding **1건** (`affected_urls`, `affected_count`).

## optional ZAP (passive only)

| Rule | 내용 |
|------|------|
| **10036** / **10036-1** / **10036-2** | `Server` 헤더 노출 |
| **10037** | `X-Powered-By` 노출 |

active scan **사용 안 함**. httpx hit URL 우선 seed → passive scan 대기 → alert 수집.  
run 전후 ZAP workspace reset (2-2/7-2와 동일).

```yaml
diagnosis_7_3:
  zap_enabled: true
  zap_max_minutes: 10
```

## 판정 규칙

| 값 패턴 | strict severity | standard (`strict: false`) |
|---------|-----------------|----------------------------|
| 버전 (`nginx/1.31.2`, `PHP/8`) | medium | medium |
| 제품명만 (`nginx`, `Express`) | **medium** | low |
| 환경명 (`staging`, `dev`) | **medium** | low |
| 기타 비어있지 않은 값 | **medium** | low |
| `webserver`, `unknown` | pass | pass |

## v1 제외

- TLS/인증서 (→ **7-4**)
- CDN 헤더 (기본 off, `include_cdn_headers: true`로 on)
