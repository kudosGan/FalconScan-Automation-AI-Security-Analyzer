# Falcon Scan: the website and the API in one container (see backend/server.py).
FROM node:20-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app/backend
ENV PYTHONUNBUFFERED=1 FALCON_DB=/data/falconscan.db FALCON_STATIC=/app/frontend/dist FALCON_COOKIE_SECURE=1
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=web /web/dist /app/frontend/dist
RUN useradd --system --create-home falcon && mkdir -p /data && chown falcon /data
USER falcon
EXPOSE 8000
# One process only (the scheduler and the SQLite file assume it). The proxy flags make the address and HTTPS of the visitor visible behind a host's load balancer.
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
