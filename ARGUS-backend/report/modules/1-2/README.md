# 1-2 최종 보고서 생성기

`data/report/1-2/latest.yaml`과 스크린샷 단계가 만든 finding별
`evidence/*/manifest.json`을 결합해 자체 포함형 HTML과 A4 PDF를 생성합니다.

finding 상세 내용은 다음 순서를 고정합니다.

1. 탐지 기법 및 테스트 방법
   - 증거 스크린샷(1번 바로 아래)
2. URL을 포함한 진단 결과 및 취약 판정 근거
3. 웹/API 개발보안 기준 기반 대응방안

진단 실행 시 `진단 결과 저장 → 증거 스크린샷 생성 → 최종 보고서 생성` 순서로
자동 실행됩니다. 스크린샷 또는 보고서 생성 실패가 이미 완료된 진단 결과를
실패 처리하지는 않으며, 각 단계의 오류 JSON을 산출물 디렉터리에 남깁니다.

직접 실행:

```bash
python report/modules/1-2/generate.py
```

PDF 없이 데이터와 HTML만 생성:

```bash
python report/modules/1-2/generate.py --no-pdf
```

산출물은 기본적으로 `data/report/1-2/final/`에 저장됩니다.

- `report-data.json`: 정규화된 보고서 데이터
- `report.html`: 브라우저 열람용 자체 포함형 HTML
- `report.pdf`: A4 PDF
- `report-manifest.json`: 생성 결과 및 원본 해시

백엔드 조회 API:

- `GET /api/diagnosis/modules/1-2/final-report`
- `GET /api/diagnosis/modules/1-2/final-report.pdf`
- `GET /api/diagnosis/modules/1-2/final-report/manifest`
