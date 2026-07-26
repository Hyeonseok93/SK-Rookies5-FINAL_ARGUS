# 2-2 모듈 MVP 스코프 — 중요 정보 파일 다운로드 가능성

KISA Web/API 개발보안 Guideline **2-2** (2장 취약한 파일처리).  
4장(접근제어)·1-4(SSRF/LFI)·3-6(백업 파일)과 **겹칠 수 있음** — finding에 `related_sections`로 표기.

---

## v1 (MVP) — 자동화 우선

**목표:** api-tree + ZAP으로 **Path Traversal / 필터 우회 / 숨은 민감 파일**을 잡고 `SectionReport`로 저장.

### 포함

| # | 가이드라인 유형 | v1 동작 |
|---|----------------|---------|
| 1 | Path Traversal | ZAP Active Scan Rule **6**, path/filename/**template** 등 후보 파라미터 |
| 2 | 필터 우회 ([표 12], null byte) | Custom payloads + `assets/path-traversal-payloads.txt` |
| 3 | 민감 파일 노출 | Hidden File **40035**, Directory **0**, `assets/forced-browse-download.txt` |
| 4 | 후보 선별 | api-tree-verified에서 path/export/report/download + `inventory/tags.py` 규칙 |
| 5 | 설계 (정적) | `path=`/`filename=` 직접 입력 API **존재 여부** → info finding (취약 행위 아님) |

### v1 입력 (ARGUS)

- `data/api-tree-verified.json` (없으면 `api-tree-ready.json`)
- `data/zap-requestor-seeds.json` (inventory build 산출)
- `config.yaml` → `zap.proxy`, `auth`, `targets`
- `data/test-accounts.json` (선택 — v1은 **단일 로그인** 또는 anonymous만)

### v1 파이프라인

```
1. load_api_tree()
2. tag_endpoints() + filter 2-2-candidates
3. design_review() → path/filename 직접 파라미터 목록
4. ensure_zap() + apply_auth (optional)
5. inject_seeds(candidates)
6. active_scan(policy=Download-Security-2-2)  # Rule 6,0,40035,40034,40032,40008
7. forced_browse(base_urls, wordlist)           # 후보 URL + wordlist append
8. collect_alerts() → map to DiagnosisFinding
9. save_report → reports/latest.yaml
```

### v1 ZAP 정책 `Download-Security-2-2`

**Unified (v2):** httpx와 ZAP이 **동일 ARGUS 판정 로직** (`analysis_mode: unified`)으로 unauth download / traversal / forced browse 실행. ZAP은 supplemental native(0, 40035, …)만 추가. Rule 6 hybrid 중복 제거.

| | httpx | ZAP |
|---|--------|-----|
| unauth download | ✅ transport=httpx | ✅ transport=zap (unified) |
| traversal + PDF leak | ✅ | ✅ 동일 `compare_to_baseline` |
| forced browse | ✅ | ✅ |
| hidden file / dir browse | wordlist | native 0, 40035, … |

**Hybrid (v1.5):** traversal payload는 ZAP `sendRequest`로 보내고, 응답은 **httpx와 동일한** `compare_to_baseline` / PDF 텍스트 분석으로 finding 생성 (`analysis_mode: hybrid`, `source: zap`). ZAP native Rule 6 alert가 없어도 PDF LFI 등 앱 특화 취약점을 ZAP phase에서 잡을 수 있음.

| Rule | 이름 |
|------|------|
| 6 | Path Traversal |
| 0 | Directory Browsing |
| 40035 | Hidden File Finder |
| 40034 | .env Information Leak |
| 40032 | .htaccess Information Leak |
| 40008 | Parameter Tampering |

참고: `zap-2-2-scan/plans/2-2-download-scan.yaml`, `scripts/run_2_2_scan.py`

### v1 Pass / Fail (자동)

| Finding | severity |
|---------|----------|
| Path Traversal alert | high |
| .env / backup / hidden file hit | high |
| Directory browsing | medium |
| Parameter tampering on file param | medium |
| `path`/`filename` 직접 파라미터 존재 (설계) | info |

### v1 제외 (의도적)

- IDOR (남의 fileId)
- 비로그인 vs 로그인 **비교** (→ v2 또는 4-4)
- 응답 body가 「중요 정보」인지 **내용 분석**
- SSRF / LFI(include) → **1-4** 모듈

---

## v2 — 접근·IDOR

| # | 유형 | v2 동작 |
|---|------|---------|
| 1 | 권한 없음 | anonymous vs authenticated probe on **2-2 candidates only** |
| 2 | IDOR | test account A fileId → request as B |
| 3 | fileId 설계 | UUID/opaque only vs enumerable id → info/warning |
| 4 | 파일 응답 휴리스틱 | Content-Disposition, application/octet-stream, PDF magic bytes |

`related_sections`: `4-3`, `4-4`, `4-5` when applicable.

---

## Onde 1차 후보 (api-tree 기준)

| Method | Path | 이유 |
|--------|------|------|
| POST | `/api/v1/report/integrated` | body `template` |
| GET | `/api/v1/admin/bookings/flights/{scheduleId}/export` | export |
| * | path에 `export`, `report`, `download`, `file`, `attach` | tags 규칙 |

프론트 URL List는 v1 **스캔 시드 아님** (SPA path only).

---

## 산출물

```
modules/2-2/
  manifest.yaml
  module.py              # v1: G22Module extends DiagnosisModule
  SCOPE.md               # this file
  assets/
    path-traversal-payloads.txt
    forced-browse-download.txt
    zap-policy.yaml      # (v1 impl) Download-Security-2-2 fragment
  reports/
    latest.yaml          # SectionReport
```

---

## 구현 체크리스트

### v1

- [ ] `inventory_service` / merge 후 `tag_endpoint()` 호출
- [ ] `diagnosis/modules/2-2/scanner.py` — ZAP orchestration (from run_2_2_scan)
- [ ] `diagnosis/modules/2-2/candidates.py` — tree filter
- [ ] `diagnosis/modules/2-2/module.py` — `G22Module.run()`
- [ ] manifest `implemented: true`, `engine: zap`
- [ ] tests: candidate filter, mock alert mapping

### v2

- [ ] dual-account IDOR runner
- [ ] anonymous auth matrix on candidates
- [ ] related_sections in findings
