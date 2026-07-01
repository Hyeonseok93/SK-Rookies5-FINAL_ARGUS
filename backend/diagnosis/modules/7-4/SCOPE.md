# 7-4 취약한 보안설정 (Web/API scope)

HTTP 응답에서 **보이는** 보안 설정만 점검. OS/WAS 파일·방화벽·DB 설정은 제외.

## v1 — httpx (always)

| Check | 조건 | strict |
|-------|------|--------|
| HSTS | HTTPS URL, `Strict-Transport-Security` 없음 | medium |
| CSP | `Content-Security-Policy` 없음 | medium / low |
| X-Frame-Options | 없음 또는 `ALLOWALL` | medium |
| X-Content-Type-Options | 없음 또는 `nosniff` 아님 | medium |
| Referrer-Policy | 없음 | low (strict만) |
| Cookie Secure | HTTPS + `Set-Cookie` without Secure | medium |
| Cookie HttpOnly | session-like name without HttpOnly | medium (strict) |
| Cookie SameSite | `SameSite=None` without Secure | high |

## ZAP (optional, passive only)

Rules: 10035, 10038, 10020, 10021, 10054, 10063

## Not in scope

- TLS cipher audit (v1.5)
- Server header disclosure (→ 7-3)
- Directory listing (→ 7-2)
