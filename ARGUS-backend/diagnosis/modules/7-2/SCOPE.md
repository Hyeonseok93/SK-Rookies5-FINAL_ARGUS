# 7-2 — 파일 목록화 가능성

## v1 — 내장 comprehensive wordlist (수동 path 불필요)

모든 Base URL에 **자동** probe:

| 소스 | 내용 |
|------|------|
| `directory-wordlist.txt` | 공통 static/upload |
| `directory-wordlist-comprehensive.txt` | Apache, nginx, Tomcat, IIS, Jetty, JBoss, PHP/CMS, Spring … |
| `2-2/forced-browse-download.txt` | 단일 segment 디렉터리명 |
| api-tree (sample/full) | 디렉터리형 path + **상위 segment** |

각 path: **`/path/`** + **`/path`** (trailing slash 유/무)

## probe_mode

| 모드 | 동작 |
|------|------|
| **base_only** | 내장 wordlist **전체** × 모든 Base |
| **sample** | + api-tree base당 N + parent dirs |
| **full** | + api-tree 디렉터리 path 전수 |

## body 시그니처

Apache `Index of`, nginx autoindex, IIS `- Directory listing`, Tomcat `<hr>`, Caddy/Lighttpd 보조.

## config (선택)

```yaml
diagnosis_7_2:
  probe_mode: base_only   # | sample | full
  sample_size: 20
  timeout: 12
```

`extra_probe_paths` — 레거시 호환만 (UI 없음).

## v1.5 — optional ZAP (Rule 0)

httpx 이후 선택 실행:

| 단계 | 동작 |
|------|------|
| seed | probe target URL을 최대 300개 균등 샘플 → `zap.urlopen` |
| active | 각 Base URL `recurse=True` active scan (Rule 0 only) |
| alerts | plugin 0 / 10033 → `7-2-directory-listing` finding |

httpx listing hit URL은 ZAP seed **우선 포함**. seed 후 passive scan 대기 → active scan.

**ZAP workspace:** 스캔 **시작 전·종료 후** `newSession(overwrite)` + alert 삭제로 2-2 등 이전 run 히스토리/alert가 섞이지 않음.

```yaml
diagnosis_7_2:
  zap_enabled: true
  zap_max_minutes: 15
```
