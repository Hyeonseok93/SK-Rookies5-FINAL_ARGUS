# 3-6 백업 파일 및 테스트 파일 존재 여부

KISA Web/API Guideline **3-6**.  
공개 경로에 **백업·테스트·디버그** 아티팩트가 노출되는지 점검.

2-2(다운로드/traversal) · 7-2(디렉터리 listing)와 겹칠 수 있음 — `related_sections` 표기.

Hidden file / ZAP depth는 **2-2**에서 수행 (3-6은 httpx wordlist 전용).

## httpx multi-pass

| Pass | 의미 |
|------|------|
| **1st anonymous** | 무인증 wordlist GET — **KISA 핵심** (fail/warn 기준) |
| **2nd+ authenticated** | 동일 URL + login cookie — **세션별** (user · admin login 등) |

로그인: `probe_auth.all_account_auths` — Test Accounts × 발견된 login URL 전부. test account 없으면 1st만.

각 Base (8080 · 5173 frontend 등) × wordlist path.

## wordlist

| 소스 | 내용 |
|------|------|
| `assets/backup-test-files.txt` | backup/test/debug 전용 |
| `2-2/forced-browse-download.txt` | 파일형 path만 필터 |

판정 (`file_rules.py`): leak markers + SPA baseline skip.

## probe_mode

| 모드 | 동작 |
|------|------|
| **base_only** | wordlist × 모든 Base |
| **sample** | + api-tree backup/test path 샘플 |
| **full** | + api-tree 파일형 path 전수 |

## config

```yaml
diagnosis_3_6:
  probe_mode: base_only
  sample_size: 20
  timeout: 8
```

## Not in scope

- Path traversal on API parameters (→ **2-2**)
- Directory listing only (→ **7-2**)
- ZAP hidden file fuzz (→ **2-2**)
