# 3-5 검색엔진 정보 노출 가능성

KISA Web/API Guideline **3-5**.  
**판정(fail/warn) 없이** robots.txt · noindex/nofollow **인벤토리** 수집.

## httpx multi-pass (2-2 auth pattern)

| Pass | Cookie/Bearer | 대상 |
|------|---------------|------|
| **anonymous** | 없음 | robots.txt + 페이지 GET |
| **authenticated** | test account × login entry | **동일 URL** 재-probe (세션별) |

로그인: `login_all_accounts` — Test Accounts × inventory/대시보드에서 발견된 **모든 login URL** (user · admin 등) 조합.  
성공한 세션마다 authenticated pass 1회. finding에 `account_email` · `login_label` · `login_url` 기록.

`test-accounts.json` + `auth` 필요. 없으면 anonymous만.

## robots.txt (anonymous)

**frontend/public Base만** (5173 등) `/robots.txt` — Disallow/Allow/Sitemap 목록 (info).  
API/WAS Base (8080 등)는 robots.txt 대상에서 **제외** (REST 서버에는 일반적으로 불필요).

Base URL은 `localhost` / `host.docker.internal` 동일 포트 중복 시 하나로 dedupe (Docker probe는 `ARGUS_PROBE_HOST` 유지).

## 페이지 probe (frontend 우선)

wordlist **없음**. api-tree GET path:

- **frontend base** (`frontend_base_url`, port 5173 등): `kind=frontend` + SPA route (`/api` JSON path 제외)
- **API base** (8080): `/` + frontend kind만 (REST `/api/v1/*` skip)

noindex/nofollow 있는 URL만 개별 info finding + pass별 summary.

**SPA 한계:** httpx 초기 HTML만 (JS 렌더 meta는 miss).

## probe_mode

| 모드 | 동작 |
|------|------|
| **base_only** | Base `/` |
| **sample** | api-tree 샘플 (기본) |
| **full** | api-tree GET 전수 |

## config

```yaml
diagnosis_3_5:
  probe_mode: sample
  sample_size: 50
  timeout: 8
```

## Not in scope

- 7-x 스타일 fail on missing robots
- ZAP / Playwright (v2)
