# 1-3 모듈 스코프 — 파라미터 값 및 히든(Hidden) 필드 조작 가능성

KISA Web/API 개발보안 Guideline **1-3** (1장 입력 데이터 보안).  
OWASP WSTG: **Business Logic / Integrity Checks** — *클라이언트가 보낸 값을 서버가 검증 없이 신뢰하는가?*

다른 점검항목과 **겹칠 수 있음** — finding에 `related_sections`로 표기.

---

## 1. 이 항목이 잡아야 하는 취약점 (핵심 정의)

> **사용자가 화면에서 바꿀 수 없거나, 바꿔서는 안 되는 값**을  
> **URL·Query·Body·Form(hidden)** 에 넣어 보냈을 때, 서버가 **그대로 반영**하는 경우.

| # | 취약 유형 | 설명 | 조작 예 |
|---|-----------|------|---------|
| **A** | **히든 필드 조작** | UI에 없거나 `type=hidden` / API body만 있는 필드 | `discount=0` → `100`, `memberId` body 추가·변경 |
| **B** | **금액·수량 조작** | 가격·보험료·마일리지·할인 등 **서버가 재계산해야 할 값** | `totalPremium=135000` → `0`, `amount=1` |
| **C** | **주체·소유자 ID 조작** | 세션/JWT와 **별도로** 사용자·주문·예약 ID를 body에 실어 보내는 API | `memberId=1` → `2` (타인 데이터) |
| **D** | **권한·역할 조 manipulation** | 가입·프로필·관리 API의 role/grade | `role=USER` → `SELLER`, `ADMIN` |
| **E** | **상태·워크플로우 조작** | UI 단계를 건너뛰거나 상태를 임의 변경 | `status=PENDING` → `PAID`, `CANCELLED` → `COMPLETED` |
| **F** | **상품·등급·옵션 조 manipulation** | UI에 없는 plan/tier/coverage 선택 | `coverageLevel=DELUXE` → `FREE`, 다른 `productId` |
| **G** | **UI 비노출 값 허용** | disabled select/radio, 관리자 전용 option을 **API로 직접** 전송 | 화면 옵션 목록 밖 enum 값 |
| **H** | **무결성 검증 부재 (약한 신호)** | 조작값이 **200 OK**로 수용되나 baseline과 동일·무해 | 서버가 값은 받지만 무시 — **info/medium** |

### 취약으로 보는 신호 (공통)

1. **반영됨** — 응답 JSON/DB/UI에 조작값이 그대로 또는 계산 결과에 반영  
2. **허용됨** — 400/422 없이 2xx, baseline과 **의미 있는 diff**  
3. **우회됨** — UI에서 막힌 값·단계를 API만으로 달성  

### 취약이 **아닌** 신호

- 400/422 등 **서버가 거절**  
- 401/403 **접근제어** (→ 4-3/4-4 쪽, 단 body `memberId`+200은 1-3)  
- 조작 후 응답이 baseline과 **완전 동일**하고 비즈니스 영향 없음  

---

## 2. 점검 대상 파라미터 (어디를 볼 것인가)

| 위치 | 1-3 해당 | 비고 |
|------|----------|------|
| **JSON body** | ✅ 1순위 | SPA/API — hidden = body 필드 |
| **HTML form hidden / POST** | ✅ | 전통 웹 |
| **Query string** | ✅ | `?price=`, `?role=` |
| **Path `{id}`** | ⚠️ 제한 | **IDOR·객체 참조**는 4-4/4-5 우선; body와 **동시에** 있으면 1-3도 |
| **Header (Cookie 제외)** | ⚠️ | `X-User-Id` 등 — 4-1과 겹칠 수 있음 |
| **Cookie / JWT 클레임 조작** | ❌ | **4-1, 4-2** |

### 민감 파라미터 이름 (후보 태깅용)

```
# 주체·소유
memberId, userId, accountId, ownerId, customerId

# 권한
role, authority, permission, isAdmin, memberRole, grade, membershipGrade

# 금액·수량
price, amount, total, totalPremium, premium, discount, mileage, quantity, qty, fee

# 상태
status, state, paymentStatus, orderStatus, bookingStatus

# 상품·옵션
productId, planId, coverageLevel, template (경로 조작 아닌 enum/value 변경만 1-3)

# 기타 비즈니스
couponId, point, points, commissionRate
```

`template`에 `../etc/passwd` → **2-2 Path Traversal** (1-3 아님).  
`template=admin_only_report` → **1-3** (enum/값 조작).

---

## 3. 다른 가이드라인과 경계

| 항목 | 1-3 | 다른 모듈 |
|------|-----|-----------|
| `price=0` body 조작 | ✅ | |
| `../../etc/passwd` in file param | ❌ | **2-2** |
| SQL `' OR 1=1` | ❌ | **1-2** |
| SSRF URL in param | ❌ | **1-4** |
| 비로그인 `/mypage` | ❌ | **4-4** |
| `GET /orders/{id}` id만 변경 | ⚠️ | **4-4 IDOR** 주; body `orderId` 조작은 **1-3** |
| `role=ADMIN` body | ✅ | **4-5** 권한상승과 **동시 표기** |
| Cookie `accessToken` 변조 | ❌ | **4-1** |
| 입력 길이 초과·형식 오류 | ⚠️ | **1-6** (1-3은 *비즈니스 값* 조작) |
| CSRF token 제거 | ⚠️ | **1-1** (체크리스트에 있으나 MVP 제외 권장) |

---

## 4. Onde 1차 후보 (api-tree·수동 시드)

| Method | Path | 의심 필드 | 1-3 유형 |
|--------|------|-----------|----------|
| POST | `/api/v1/insurances/calculate` | `productId`, `totalPremium`, … | B, F |
| POST | `/api/v1/report/integrated` | `memberId` (body, UI hidden) | A, C |
| POST | `/api/v1/auth/signup` | `role` | D |
| POST | `/api/v1/payments/*` (예약·결제) | `amount`, `memberId` | B, C |
| POST | `/api/v1/reservations/*` | `memberId`, `status`, 금액 필드 | B, C, E |
| PUT/PATCH | 프로필·마일리지 | `mileage`, `grade`, `role` | B, D |

프론트 **hidden input** ↔ API body 매핑은 v2(Playwright) — MVP는 **api-tree body 필드 = hidden 후보**.

---

## 5. v1 (MVP) — 자동화 범위

### 포함

| # | 동작 |
|---|------|
| 1 | `api-tree-verified.json`에서 **body/query param ≥ 1** 인 POST/PUT/PATCH 후보 |
| 2 | **민감 이름 regex**로 조작 대상 필드 선별 |
| 3 | **baseline** (정상 probe body) + **필드당 1개 mutation** (2-2 `inject_json_body` 패턴) |
| 4 | **로그인 세션** probe (대부분 1-3은 authenticated) |
| 5 | 응답 **JSON diff** + 비즈니스 필드 변화로 A~F 분류 |
| 6 | **Replay**: baseline / mutated / compare HTTP 패널 |
| 7 | 설계 **info**: hidden 후보 필드 목록 (body에 있으나 OpenAPI required=false 등) |

### Mutation 세트 (필드 타입별)

| 타입 | mutation 예 |
|------|-------------|
| ID | `0`, `-1`, `999999`, `baseline+1` |
| role | `ADMIN`, `ROLE_ADMIN`, `SELLER`, `SUPER_ADMIN` |
| money | `0`, `1`, `-1`, `999999999` |
| status | `COMPLETED`, `CANCELLED`, `APPROVED`, `PAID` |
| enum/product | 목록 밖 문자열, `0`, `null` |
| hidden test | 필드 **삭제**, 필드 **추가** (`isAdmin: true`) |

### Finding severity (초안)

| severity | 조건 |
|----------|------|
| **high** | 조작값이 응답/비즈니스 결과에 **반영** (타인 ID, 0원, role 상승 등) |
| **medium** | 2xx + baseline 대비 **의미 있는 JSON diff**, 반영 여부 불명확 |
| **info** | hidden 후보 필드 존재, 또는 약한 검증(동일 200) |

### v1 제외 (의도적)

- HTML DOM hidden 파싱 (→ v2 Playwright)
- ZAP 40008 only 스캔 (→ v1.5 보조)
- Path traversal payload (→ **2-2**)
- CSRF token tampering (→ **1-1**)
- Cookie/JWT 조작 (→ **4-1**)

---

## 6. v2 — 확장

| # | 내용 |
|---|------|
| 1 | Playwright: 폼 hidden 값 변경 후 submit |
| 2 | ZAP Rule **40008** Parameter Tampering merge |
| 3 | 계정 A 로그인 + **계정 B** `memberId` 교차 probe |
| 4 | Value Generator 스타일 **필드명→mutation** YAML 확장 |

---

## 7. 산출물

```
modules/1-3/
  SCOPE.md                 # this file
  manifest.yaml
  module.py
  scanner.py
  candidates.py
  param_classify.py
  mutations.py
  probes.py
  compare.py
  design_review.py
  assets/
    sensitive-param-patterns.yaml
    mutation-values.yaml
  reports/
    latest.yaml
```

---

## 8. 구현 체크리스트

### v1

- [ ] `SCOPE.md` 확정 (이 문서)
- [ ] `sensitive-param-patterns.yaml`
- [ ] `candidates.py` + inventory tag `1-3-candidate`
- [ ] `probes.py` baseline + single-param mutation
- [ ] `compare.py` JSON/business diff
- [ ] `scanner.py` + `module.py`
- [ ] PoC: `insurances/calculate`, `report/integrated`
- [ ] Replay baseline / mutated / compare
