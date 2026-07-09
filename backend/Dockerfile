FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Screenshot evidence capture (5-2 등) uses Playwright headless Chromium.
RUN playwright install --with-deps chromium

COPY app ./app
COPY diagnosis ./diagnosis
COPY inventory ./inventory
COPY integrations ./integrations
COPY parsers ./parsers
COPY screenshot ./screenshot
COPY config.yaml config.docker.yaml ./

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
