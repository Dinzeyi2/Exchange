# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS ui
WORKDIR /build/ui
COPY ui/package*.json ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    npm ci --strict-ssl=true --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 EXCHANGE_DATA_DIR=/data EXCHANGE_MODE=demo EXCHANGE_UI_DIR=/app/ui/dist
WORKDIR /app
COPY requirements.lock pyproject.toml ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --require-hashes -r requirements.lock
COPY node/ node/
COPY sim/ sim/
COPY certify/ certify/
COPY catalog/ catalog/
COPY --from=ui /build/ui/dist/ ui/dist/
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --no-deps . && \
    useradd --uid 10001 --create-home exchange && mkdir /data && chown exchange:exchange /data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3)"
CMD ["exchange", "serve", "--host", "0.0.0.0"]
