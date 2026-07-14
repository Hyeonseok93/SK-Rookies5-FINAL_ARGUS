# 7-4 최종 보고서 생성기

`data/report/7-4/latest.yaml`과 스크린샷 단계의
`evidence/capture-summary.json`을 case ID로 연결해 자체 포함형 HTML과 A4 PDF를 생성합니다.

상세 finding 순서:

1. 탐지 기법 및 테스트 방법
   - 증거 스크린샷
2. 대상 URL 또는 의존성 좌표를 포함한 진단 결과 및 취약 판정 근거
3. 웹/API 개발보안 기준 기반 대응방안

오픈소스 의존성 취약점 점검에는 **deps 파일이 필수**입니다. Swagger, API List,
URL List, Base URL에는 서버가 실제 사용하는 라이브러리와 설치 버전이 없으므로,
deps 파일이 있어야 취약 버전 범위를 정확하게 비교하고 오탐을 방지할 수 있습니다.

7-4 진단 실행 시 `진단 → 증거 스크린샷 → 최종 HTML/PDF` 순서로 자동 실행됩니다.
생성 위치는 `data/report/7-4/final/`입니다.

```bash
python report/modules/7-4/generate.py
python report/modules/7-4/generate.py --no-pdf
```

조회 API:

- `GET /api/diagnosis/modules/7-4/final-report`
- `GET /api/diagnosis/modules/7-4/final-report.pdf`
- `GET /api/diagnosis/modules/7-4/final-report/manifest`
