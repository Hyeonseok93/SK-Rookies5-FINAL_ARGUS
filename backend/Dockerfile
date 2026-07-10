FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# 1-5의 로그인 리다이렉트 브라우저 검증(reflected_browser_verify.py)이 Chromium을 실행한다 —
# pip 패키지만 설치하면 파이썬 바인딩만 들어오고 실제 브라우저 바이너리/공유 라이브러리는
# 없어서 BrowserType.launch가 실패한다(container-only 수동 설치는 재빌드 시 사라짐).
RUN playwright install --with-deps chromium

COPY app ./app
COPY diagnosis ./diagnosis
COPY inventory ./inventory
COPY integrations ./integrations
COPY parsers ./parsers
COPY config.yaml config.docker.yaml ./

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
