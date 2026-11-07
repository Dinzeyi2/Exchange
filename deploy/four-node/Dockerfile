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
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 EXCHANGE_UI_DIR=/app/ui/dist
WORKDIR /app
COPY requirements.lock pyproject.toml ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --require-hashes -r requirements.lock
COPY node/ node/
COPY certify/ certify/
COPY sim/ sim/
COPY --from=ui /build/ui/dist/ ui/dist/
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir --no-deps . && \
    useradd --uid 10001 --create-home exchange && mkdir /data && chown exchange:exchange /data
USER 10001:10001
EXPOSE 8443 9443 8080
ENTRYPOINT ["exchange", "serve", "--config", "/config/node.yaml"]
