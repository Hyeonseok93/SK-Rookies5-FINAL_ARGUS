# ARGUS — Attack Surface Intelligence Platform

프론트엔드(Vite + React + Tailwind) + 백엔드(FastAPI) 모노레포.

## 구조

```
ARGUS_1/
  backend/     FastAPI — 공격 표면 지도(api-tree) 수집 API
  frontend/    React 대시보드
```

## 빠른 시작

### Backend (포트 8000)

```powershell
cd ARGUS_1/backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend (포트 5173)

```powershell
cd ARGUS_1/frontend
npm install
npm run dev
```

브라우저: http://localhost:5173

---

## Docker로 실행 (권장)

**사전 조건:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) 설치 후 실행

```powershell
cd c:\Users\hyunm\WorkStation\Zap\ARGUS_1
docker compose up --build
```

| 서비스 | URL |
|--------|-----|
| 대시보드 | http://localhost:5174 |
| API | http://localhost:8001 |
| API 문서 | http://localhost:8001/docs |

> **포트 안내:** Onde 스택이 `5173`(frontend), `8080`/`8081`(API)을 쓰므로 ARGUS는 `5174`/`8001`을 사용합니다.

중지:

```powershell
docker compose down
```

백그라운드 실행:

```powershell
docker compose up --build -d
```

로그 확인:

```powershell
docker compose logs -f
```

**볼륨:** `../`(Zap 루트) → 컨테이너 `/workspace` — Onde MD·swagger.json 읽기  
**산출물:** `backend/data/` — api-tree.json 등 호스트에 저장

---

## API

| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/health` | 헬스체크 |
| POST | `/api/inventory/build` | MD + OpenAPI merge → api-tree 생성 |
| GET | `/api/inventory/stats` | 통계 |
| GET | `/api/inventory/endpoints` | 엔드포인트 목록 (필터/페이지) |
| GET | `/api/inventory/tree` | 전체 api-tree JSON |

## 설정

`backend/config.yaml` — Markdown/OpenAPI 경로 및 base URL.

기본값은 Zap 워크스페이스의 Onde MD + argus/swagger.json 을 가리킵니다.
