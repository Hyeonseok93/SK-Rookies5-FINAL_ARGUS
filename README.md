# <img src=".github/readme/logo.png" alt="ARGUS" height="48" /> ARGUS (웹·API 취약점 진단 플랫폼)

## 💻 Developers

| [<img src="https://github.com/nirey-l.png" width="80" height="80" alt="이예린"/>](https://github.com/nirey-l) | [<img src="https://github.com/Eojinn.png" width="80" height="80" alt="김어진"/>](https://github.com/Eojinn) | [<img src="https://github.com/Hyeonseok93.png" width="80" height="80" alt="김현석"/>](https://github.com/Hyeonseok93) | [<img src="https://github.com/pjcosmos.png" width="80" height="80" alt="박진아"/>](https://github.com/pjcosmos) | [<img src="https://github.com/yoojisoo99.png" width="80" height="80" alt="유지수"/>](https://github.com/yoojisoo99) | [<img src="https://github.com/JangSeonguk1011.png" width="80" height="80" alt="장성욱"/>](https://github.com/JangSeonguk1011) | [<img src="https://github.com/hongjiho5148.png" width="80" height="80" alt="홍지호"/>](https://github.com/hongjiho5148) |
| :----------------------------------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------------------------------: |
| [이예린(팀장)](https://github.com/nirey-l) | [김어진](https://github.com/Eojinn) | [김현석](https://github.com/Hyeonseok93) | [박진아](https://github.com/pjcosmos) | [유지수](https://github.com/yoojisoo99) | [장성욱](https://github.com/JangSeonguk1011) | [홍지호](https://github.com/hongjiho5148) |

---

> [!NOTE]
> **SK쉴더스 루키즈 5기** 최종 프로젝트에서, 취약점 진단·모의해킹을 수행하는 **진단 플랫폼**입니다. 실증 대상(타깃)은 [ONDE](https://github.com/Hyeonseok93/SK-Rookies5-FINAL_ONDE) 여행 플랫폼입니다.

## 🚀 Overview

사람이 엔드포인트를 하나씩 눌러 보던 취약점 검사를, 항목별 모듈로 빠르게 돌릴 수 있게 만든 **웹·API 보안 진단 대시보드**입니다. **ARGUS**는 대상 서비스의 Attack Surface를 모으고, KISA 웹/API 개발보안 가이드라인 항목에 맞춰 스캔한 뒤, 증적 스크린샷과 결과서 PDF까지 남깁니다.

React 대시보드에서 인벤토리·진단·리포트를 다루고, FastAPI가 **수집(Verify/Discover) · 가이드라인별 진단 모듈 · Playwright 증적 캡처 · PDF 렌더**를 오케스트레이션합니다. 진단 엔진 옆에는 **OWASP ZAP** 데몬이 붙어 패시브/액티브 시그널을 보강합니다.

**데이터 수집 → 항목별 진단 → 스크린샷 캡처 → 결과서 PDF** 흐름 위에 JWT 멀티유저 워크스페이스, Docker Compose 로컬 기동, AWS·Terraform·GitHub Actions 배포를 붙여 둔 진단 플랫폼입니다.

---

## 🛠 Built With

<p>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/typescript.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/typescript.png">
  <img src=".github/readme/badges/dark/typescript.png" alt="TypeScript" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/python.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/python.png">
  <img src=".github/readme/badges/dark/python.png" alt="Python" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/react.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/react.png">
  <img src=".github/readme/badges/dark/react.png" alt="React" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/vite.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/vite.png">
  <img src=".github/readme/badges/dark/vite.png" alt="Vite" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/tailwindcss.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/tailwindcss.png">
  <img src=".github/readme/badges/dark/tailwindcss.png" alt="Tailwind CSS" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/fastapi.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/fastapi.png">
  <img src=".github/readme/badges/dark/fastapi.png" alt="FastAPI" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/zap.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/zap.png">
  <img src=".github/readme/badges/dark/zap.png" alt="OWASP ZAP" height="28" />
</picture>
<br>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/playwright.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/playwright.png">
  <img src=".github/readme/badges/dark/playwright.png" alt="Playwright" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/docker.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/docker.png">
  <img src=".github/readme/badges/dark/docker.png" alt="Docker" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/nginx.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/nginx.png">
  <img src=".github/readme/badges/dark/nginx.png" alt="Nginx" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/terraform.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/terraform.png">
  <img src=".github/readme/badges/dark/terraform.png" alt="Terraform" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/githubactions.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/githubactions.png">
  <img src=".github/readme/badges/dark/githubactions.png" alt="GitHub Actions" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/jwt.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/jwt.png">
  <img src=".github/readme/badges/dark/jwt.png" alt="JWT" height="28" />
</picture>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/badges/dark/openapi.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/readme/badges/light/openapi.png">
  <img src=".github/readme/badges/dark/openapi.png" alt="OpenAPI" height="28" />
</picture>
</p>

<details>
<summary><strong>기술 스택 상세 보기</strong></summary>

<br>

<div align="center">

<table align="center">
  <thead>
    <tr>
      <th align="left">구분</th>
      <th align="left">기술</th>
      <th align="left">역할</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="left"><strong>Frontend Core</strong></td>
      <td align="left">TypeScript, React 19, Vite 8</td>
      <td align="left">진단 대시보드 SPA 렌더링·번들</td>
    </tr>
    <tr>
      <td align="left"><strong>UI</strong></td>
      <td align="left">Tailwind CSS 4, Lucide</td>
      <td align="left">Attack Surface·Diagnosis·Report UI</td>
    </tr>
    <tr>
      <td align="left"><strong>Backend Core</strong></td>
      <td align="left">Python 3, FastAPI, Uvicorn, Pydantic</td>
      <td align="left">REST API, 진단 오케스트레이션</td>
    </tr>
    <tr>
      <td align="left"><strong>Diagnosis</strong></td>
      <td align="left">가이드라인 모듈(<code>diagnosis/</code>), httpx, ZAP API</td>
      <td align="left">KISA 항목별 스캔·판정·리플레이</td>
    </tr>
    <tr>
      <td align="left"><strong>Evidence</strong></td>
      <td align="left">Playwright, Pillow, ReportLab / pypdf</td>
      <td align="left">증적 스크린샷·결과서 PDF</td>
    </tr>
    <tr>
      <td align="left"><strong>Auth / Isolation</strong></td>
      <td align="left">JWT (PyJWT), bcrypt, Fernet</td>
      <td align="left">멀티유저 로그인, 계정 암호 at-rest, 유저별 workspace</td>
    </tr>
    <tr>
      <td align="left"><strong>Inventory</strong></td>
      <td align="left">OpenAPI 업로드, api-tree, Discover/Verify</td>
      <td align="left">Attack Surface 수집·검증·ZAP 시드</td>
    </tr>
    <tr>
      <td align="left"><strong>Build &amp; Container</strong></td>
      <td align="left">Docker, Docker Compose, Nginx, ECR</td>
      <td align="left">FE/BE/ZAP 로컬·운영 기동</td>
    </tr>
    <tr>
      <td align="left"><strong>Infrastructure</strong></td>
      <td align="left">Terraform, VPC, ALB, EC2, EBS, S3, Route53, ACM, Secrets Manager, SSM</td>
      <td align="left">IaC 기반 네트워크·컴퓨트·시크릿·관측</td>
    </tr>
    <tr>
      <td align="left"><strong>CI/CD &amp; Ops</strong></td>
      <td align="left">GitHub Actions (OIDC), ECR Push, SSM Deploy</td>
      <td align="left">FE/BE 이미지 빌드·배포 파이프라인</td>
    </tr>
  </tbody>
</table>

</div>

</details>

---

## 🖥️ Preview · [자세히 보기](https://bulldog93.tistory.com/49)

<div align="center">
  <img src=".github/readme/preview.png" alt="ARGUS Attack Surface" width="900" />
  <p>Attack Surface — 엔드포인트 인벤토리와 Verify 결과</p>
</div>

<div align="center">

<table align="center">
  <thead>
    <tr>
      <th align="left">화면</th>
      <th align="left">설명</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="left">📡 Attack Surface</td>
      <td align="left">Base URL·로그인·테스트 계정, OpenAPI/업로드 기반 API 트리, Verify/Discover</td>
    </tr>
    <tr>
      <td align="left">🧪 Diagnosis</td>
      <td align="left">KISA 가이드라인 섹션별 모듈 실행, 진행률·옵션·취소</td>
    </tr>
    <tr>
      <td align="left">🔎 Findings</td>
      <td align="left">항목별 판정·증거·리플레이, 심각도 요약</td>
    </tr>
    <tr>
      <td align="left">🖼 Evidence</td>
      <td align="left">Playwright 증적 스크린샷 캡처·열람</td>
    </tr>
    <tr>
      <td align="left">📄 Report</td>
      <td align="left">섹션/종합 결과서 PDF 생성·다운로드</td>
    </tr>
    <tr>
      <td align="left">🔐 Auth</td>
      <td align="left">JWT 로그인·(로컬) 회원가입, 유저별 <code>data/users/{id}</code> 워크스페이스</td>
    </tr>
  </tbody>
</table>

</div>

---

## 🌟 Key Implementation

1. **Attack Surface 수집 · Verify / Discover**  
   OpenAPI·업로드·베이스 URL로 엔드포인트를 모으고, ZAP/httpx로 응답을 검증합니다.
   - Discover는 ZAP OpenAPI import · seed probe · spider 흐름을 탑니다.
   - 결과는 `api-tree` / verified 트리로 남겨 이후 진단 모듈 입력으로 씁니다.

2. **가이드라인별 진단 모듈 (1-1 … 8-1)**  
   KISA 웹/API 개발보안 가이드라인 항목을 섹션 모듈로 나눕니다.
   - XSS/CSRF, Injection, 업로드, IDOR/다운로드, 인증·세션, 헤더·설정 등을 모듈 단위로 실행합니다.
   - httpx 프로브와 ZAP 패시브/액티브 시그널을 항목에 맞게 조합합니다.

3. **증적 스크린샷 · 결과서 PDF**  
   진단 후 Playwright로 증거 보드를 캡처하고, ReportLab 기반으로 PDF를 만듭니다.
   - 섹션별 evidence 디렉터리에 이미지를 쌓고 대시보드에서 열람합니다.
   - 결과서는 다운로드 API로 바로 받을 수 있습니다.

4. **멀티유저 워크스페이스**  
   JWT 인증 후 사용자마다 `data/users/{user_id}/` 아래 인벤토리·계정·리포트를 분리합니다.
   - 테스트 계정 비밀번호는 at-rest 암호화(`enc:`) + API 마스킹합니다.
   - 진단/Discover progress도 유저 단위로 격리합니다.

5. **공유 ZAP · 직렬화 배포**  
   Backend EC2(또는 Compose)에서 ZAP 데몬을 같은 Docker 네트워크에 두고 API key로만 접근합니다.
   - 호스트에 8090을 열지 않고, 진단/Discover 잡은 전역 락으로 직렬화합니다.
   - ZAP 이미지는 public `zaproxy/zap-stable`을 사용합니다.

---

## 🗂 Diagnosis Catalog & Flow

FastAPI가 **인벤토리 · 인증 프로브 · 가이드라인 진단 · 스크린샷 · 리포트** 를 한 파이프라인으로 묶습니다.

- **수집:** Base URL / 로그인 엔드포인트 / 테스트 계정 / OpenAPI·소스 업로드 → Attack Surface
- **진단:** 섹션 ID(`1-1` … `8-1`)별 모듈 실행 → findings YAML + evidence
- **산출:** 스크린샷 캡처 요약 · PDF 결과서

주요 API 표면은 `/api/auth`, `/api/inventory`, `/api/diagnosis`, `/api/base-urls`, `/api/login-endpoints`, `/api/test-accounts` 등이며, 프론트는 Bearer JWT로 호출합니다.

> 자세한 소개는 [기술 블로그(ARGUS)](https://bulldog93.tistory.com/49)에서 다룹니다.

---

## 📂 Project Structure

```text
SK-Rookies5-FINAL_ARGUS/
┣━━ 📂 .github/
┃   ┣━━ 📂 workflows/                     # PR CI · FE/BE ECR build-push
┃   ┗━━ 📂 readme/                        # README 에셋 (logo · preview · infra)
┃       ┣━━ 🖼️ logo.png
┃       ┣━━ 🖼️ preview.png
┃       ┣━━ 🖼️ ARGUS-infrastructure.drawio.png
┃       ┣━━ 🖼️ ARGUS-infrastructure.drawio.svg
┃       ┗━━ 📄 ARGUS-infrastructure.drawio
┣━━ 📂 ARGUS-frontend/                    # React 진단 대시보드
┃   ┣━━ 📂 src/
┃   ┃   ┣━━ 📂 components/                # Attack Surface · Diagnosis · Report · Login
┃   ┃   ┣━━ 📂 lib/                       # api · auth
┃   ┃   ┗━━ 📄 App.tsx
┃   ┣━━ 📄 Dockerfile
┃   ┗━━ 📄 package.json
┣━━ 📂 ARGUS-backend/                     # FastAPI · 진단 엔진
┃   ┣━━ 📂 app/                           # routers · services · auth · workspace
┃   ┣━━ 📂 diagnosis/                     # 가이드라인 모듈 · replay · zap_passive
┃   ┣━━ 📂 inventory/                     # OpenAPI · api-tree · merge
┃   ┣━━ 📂 screenshot/                    # Playwright 증적 캡처
┃   ┣━━ 📂 report/                        # PDF 렌더러
┃   ┣━━ 📂 integrations/zap/              # ZAP client · exclusive lock
┃   ┣━━ 📂 tests/
┃   ┣━━ 📄 Dockerfile
┃   ┗━━ 📄 requirements.txt
┣━━ 📂 ARGUS-infra/                       # Terraform · CD
┃   ┣━━ 📂 terraform/
┃   ┣━━ 📂 deploy/                        # prod compose (SSM)
┃   ┗━━ 📂 .github/workflows/             # deploy.yml · terraform-plan
┣━━ 📄 docker-compose.yml                 # zap · backend · frontend (local)
┣━━ 📄 docker-compose.backend.prod.yml
┣━━ 📄 docker-compose.frontend.prod.yml
┗━━ 📄 README.md
```

---

## 🏗 Infrastructure Overview

<div align="center">
  <img src=".github/readme/ARGUS-infrastructure.drawio.png" alt="ARGUS Infrastructure" width="1000" />
</div>

**Route53 → ALB(ACM) → Frontend EC2(Nginx:80) · Backend EC2(FastAPI:8001 + ZAP:8090 + EBS)** 로 이어지는 AWS 기반 아키텍처입니다. Public에는 ALB·FE·NAT, Private에는 BE·ZAP·데이터가 있습니다. 배포는 **GitHub Actions → ECR → SSM(compose up)** 으로 자동화됩니다.

> 네트워크 분리·Secrets Manager·ZAP 내부망 전용·CI/CD 등 상세 설계는 [기술 블로그(ARGUS)](https://bulldog93.tistory.com/49)와 `ARGUS-infra/terraform`을 참고하세요.

---

## ⚙️ Getting Started

### Prerequisites

- Python 3.11+ (로컬 백엔드 시)
- Node.js 20+ 및 npm (로컬 프론트 시)
- Docker / Docker Compose (권장)

### 1. 레포지토리 클론

```bash
git clone https://github.com/Hyeonseok93/SK-Rookies5-FINAL_ARGUS.git
cd SK-Rookies5-FINAL_ARGUS
```

### 2. 환경 변수 (선택)

루트 또는 셸에 로컬용 값을 둘 수 있습니다. Compose는 미설정 시 개발용 기본값을 씁니다.

```env
ZAP_API_KEY=changeme-zap-key
JWT_SECRET=argus-dev-jwt-secret-change-me
CREDENTIALS_KEY=argus-dev-credentials-key-change-me
ARGUS_ALLOW_PUBLIC_REGISTER=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

> 운영(prod compose)에서는 `ARGUS_ENV=production` · 시크릿 fail-closed · 공개 register 비활성입니다. 로컬 기본 비밀번호를 운영에 쓰지 마세요.

### 3. 통합 실행 (Docker Compose)

루트에서 ZAP · Backend · Frontend를 한 번에 띄웁니다.

```bash
docker compose up --build
```

| 서비스 | URL |
|--------|-----|
| Frontend | http://localhost:5174 |
| Backend API | http://localhost:8001 |
| Health | http://localhost:8001/api/health |
| ZAP | Compose 내부 `http://zap:8090` (호스트 미공개) |

첫 화면에서 계정을 만들거나(`ARGUS_ALLOW_PUBLIC_REGISTER=true`), `ADMIN_USERNAME` / `ADMIN_PASSWORD`로 부트스트랩된 계정으로 로그인합니다.

> Docker 없이 돌리려면 별도로 ZAP를 띄운 뒤 `ARGUS-backend`에서 `uvicorn app.main:app --reload --port 8000`, 프론트는 `ARGUS-frontend`에서 `npm install && npm run dev`를 사용하고 `ZAP_PROXY` / `ZAP_API_KEY`를 맞춥니다.
