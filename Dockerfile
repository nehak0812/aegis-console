# AEGIS — Cyber Risk Operations Center
# Stage 1 builds the console (React/Vite); stage 2 runs the Python API, scheduler and collectors.

FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8 \
    AEGIS_DATA_DIR=/data \
    HOST=0.0.0.0
# curl is used for the few government feeds whose CDN rejects Python TLS clients (CISA)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY aegis/ ./aegis/
COPY tests/ ./tests/
COPY run.py README.md ./
COPY --from=web /web/dist ./web/dist
# /data holds the SQLite database and cached bulk files. On Railway, attach a volume at /data to keep it across deploys.
RUN mkdir -p /data
EXPOSE 8000
CMD ["python", "run.py"]
