# syntax=docker/dockerfile:1.7
# urkey self-hosted images (ADR 0018). Build from the repository root, normally via compose.yaml:
#   docker compose up -d --build
# Targets: `api` (the Worker in workerd via Miniflare, D1 as SQLite) and `web` (Caddy serving the
# app and fronting the API).
#
# Behind a TLS-intercepting proxy, pass its CA as a build secret:
#   docker compose build --secret ... (or: docker build --secret id=ca,src=/path/ca.pem ...)
# The secret is used only while downloading packages and is not stored in any image layer.

ARG RUST_VERSION=1.97.0
ARG NODE_IMAGE=node:22.23.5-bookworm-slim
ARG CADDY_IMAGE=caddy:2.10.2-alpine

# ---------------------------------------------------------------- 1. WASM core
FROM rust:${RUST_VERSION}-slim-bookworm AS wasm
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca CARGO_HTTP_CAINFO=/run/secrets/ca; fi; \
    rustup target add wasm32-unknown-unknown \
    && cargo install --locked wasm-pack@0.15.1 wasm-bindgen-cli@0.2.130
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca CARGO_HTTP_CAINFO=/run/secrets/ca; fi; \
    wasm-pack build crates/wasm-bindings --target web --release --out-dir /out/wasm

# ---------------------------------------------------------------- 2. web app + API bundle
FROM ${NODE_IMAGE} AS build
ENV CF_SEND_TELEMETRY=false CI=true
# workerd (used by the Vite plugin and Miniflare) refuses to start without system CA
# certificates. Take Debian's bundle from the Rust stage instead of running apt.
COPY --from=wasm /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/web/package.json apps/web/
COPY cloud/workers/api/package.json cloud/workers/api/
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi; \
    corepack enable && corepack prepare pnpm@10.28.0 --activate \
    && pnpm install --frozen-lockfile
COPY tsconfig.base.json ./
COPY apps/web apps/web
COPY cloud/workers/api cloud/workers/api
COPY deploy/selfhost deploy/selfhost
COPY --from=wasm /out/wasm apps/web/src/wasm
# The app's CSP `connect-src` and API calls use this origin, so it is fixed at build time.
ARG URKEY_API_ORIGIN
RUN test -n "$URKEY_API_ORIGIN" || (echo "URKEY_API_ORIGIN build arg is required" && exit 1); \
    mkdir -p /out && cd apps/web && VITE_API_ORIGIN="$URKEY_API_ORIGIN" pnpm exec vite build \
    && node /src/deploy/selfhost/headers-to-caddy.mjs .cloudflare/output/v1/workers/default/assets/_headers /out/headers.caddy \
    && cp .cloudflare/output/v1/workers/default/assets/release.json /out/release.json
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi; \
    cd cloud/workers/api && pnpm exec cf build \
    && cd /src && pnpm --filter api deploy --prod --legacy /out/api \
    && mkdir -p /out/api/.cloudflare && cp -r cloud/workers/api/.cloudflare/output /out/api/.cloudflare/ \
    && rm -rf /out/api/test /out/api/src

# ---------------------------------------------------------------- 3a. API runtime
FROM ${NODE_IMAGE} AS api
ENV NODE_ENV=production URKEY_DATA=/data PORT=8787
COPY --from=wasm /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY --from=build --chown=node:node /out/api /app
RUN mkdir -p /data && chown node:node /data && chmod 700 /data
USER node
EXPOSE 8787
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD node -e "fetch('http://127.0.0.1:8787/v1/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "selfhost/server.mjs"]

# ---------------------------------------------------------------- 3b. web front end
FROM ${CADDY_IMAGE} AS web
COPY --from=build /src/apps/web/.cloudflare/output/v1/workers/default/assets /srv
RUN rm -f /srv/_headers
COPY deploy/selfhost/Caddyfile deploy/selfhost/tls-auto.caddy deploy/selfhost/tls-internal.caddy /etc/caddy/
COPY --from=build /out/headers.caddy /etc/caddy/headers.caddy
