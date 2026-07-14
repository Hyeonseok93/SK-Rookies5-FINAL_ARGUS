FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install --with-deps chromium
# fonts-noto-cjk: proper Korean/CJK glyphs for Chromium (PDF report rendering,
# screenshot capture) — without it the container falls back to WenQuanYi Zen
# Hei, a low-quality substitute that visibly differs from what a Korean
# Windows/macOS dev machine renders (Malgun Gothic / Apple SD Gothic Neo).
RUN apt-get update \
    && apt-get install -y --no-install-recommends scrot xauth fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

COPY app ./app
COPY diagnosis ./diagnosis
COPY screenshot ./screenshot
COPY report ./report
COPY inventory ./inventory
COPY integrations ./integrations
COPY parsers ./parsers
COPY config.yaml config.docker.yaml ./

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
