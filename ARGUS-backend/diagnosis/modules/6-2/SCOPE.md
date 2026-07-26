# 6-2 일괄적인 오류 처리 페이지 존재 여부 (v1 — 로그인)



Web/API에서 **로그인 실패 응답이 계정 존재 여부를 구분하지 않는지** 점검.



## v1 — httpx



**Login targets** — api-tree에서 POST 로그인 API **자동 탐지** (`login_discovery_service.py`).



각 target마다:



| 시나리오 | 입력 |

|----------|------|

| **A** | 존재하는 계정 + **틀린 비밀번호** |

| **B** | 없는 계정 + **틀린 비밀번호** (둘 다 틀림) |

| **C** | 없는 계정 + **맞는 비밀번호** (테스트 계정 PW) |

**A·B·C 전부** 동일한 실패 응답이어야 pass.



비교: HTTP status, JSON message/error/code, body fingerprint.



- **동일** → pass (info, A/B/C 메시지 표시)

- **상이** → fail (medium) — 계정 enumeration / 무작위 대입 위험



## 로그인 target 출처

| 출처 | 설명 |
|------|------|
| `inventory` | Build/Discover 후 api-tree 휴리스틱 탐지 (POST + login path + credential body) |

## 설정

- **인벤토리:** Build/Discover → Verify (api-tree)
- **계정:** Test Accounts
- **필드명:** `config.yaml` → `auth.id_field` / `pw_field`



## ZAP 40023 (optional, default on)

- Active Scan rule **40023** — Possible Username Enumeration (Beta add-on)
- Per login target: ZAP Context + `jsonBasedAuthentication` (API) or `formBasedAuthentication` (page)
- Known username = probe account email; ZAP compares valid vs invalid username responses
- `zap_enabled: false` or ZAP unavailable → httpx only

## Not in scope (v1)

- 모달 UI 직접 조작 (등록한 URL/API에 POST 프로브)
- 404/500 커스텀 오류 페이지 통일성
- CAPTCHA / MFA

