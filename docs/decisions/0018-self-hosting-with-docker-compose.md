# 0018. Self-hosting with Docker Compose

- Status: Accepted (owner request, 2026-11-27)
- Date: 2026-11-27
- Requirements: R-SEC-10, R-SEC-13; threat model T-3, T-17, T-20, T-26

## Context
The owner asked for a way to run urkey on their own machine or server with Docker Compose, as an
alternative to Cloudflare. The API is a Cloudflare Worker that uses D1 (ADR 0009, 0014). It
should run unchanged, so self-hosting does not become a second code path that the security
review has to cover separately.

## Decision
- **Same Worker bundle, same runtime.** The API container runs the `cf build` output in
  **workerd**, through Miniflare's programmatic API (`cloud/workers/api/selfhost/server.mjs`).
  D1 is Miniflare's SQLite-backed D1, persisted in the `urkey-data` volume. Migrations from
  `migrations/` are applied once each and recorded in `d1_migrations`. The retention job runs
  at start and every 6 hours.
- **No development tooling in production.** The Vite dev and preview servers are not used. The
  server turns off Miniflare's Local Explorer (it can query D1), observability capture (traces
  can contain session tokens), telemetry, the dev registry, and fetching `Request.cf` from
  Cloudflare. Its public listener forwards only `/v1/*`.
- **Caddy is the only public entry point.**
  - It serves the static web build. Its headers are generated from the same `_headers` file the
    Cloudflare deployment uses (`headers-to-caddy.mjs`), so the CSP, Trusted Types and the
    others are identical.
  - It proxies only `/v1/*` of the API origin.
  - App and API stay on **separate origins** (R-SEC-13): separate ports on localhost, or
    separate hostnames with HTTPS.
- **Client IP for rate limits.** The API container is not published. Caddy always replaces
  `X-Forwarded-For` with the real peer address, and the server turns that into
  `CF-Connecting-IP`. Any client-supplied value is overwritten.
- **Secrets.** The prelogin secret is generated on first start inside the data volume (0600).
  Nothing secret is baked into images or compose files.
- **Hardening.** The API runs as a non-root user with a read-only root filesystem (tmpfs for
  scratch files), all capabilities dropped and `no-new-privileges`. Caddy keeps only
  `NET_BIND_SERVICE`. By default, ports are published on 127.0.0.1 only.
- **TLS.** `http://localhost` origins need no TLS, because browsers treat localhost as a secure
  context. Other devices need HTTPS (`compose.tls.yaml`): Let's Encrypt for public names, or
  Caddy's local CA for LAN names (`URKEY_TLS_MODE=internal`).

## Alternatives considered
- **`cf dev` / `vite preview` in a container:** exposes `/__debug` and the Local Explorer, and
  stores request traces. Rejected.
- **Rewriting the API for Node + SQLite:** a second implementation to review and keep in step.
  Rejected.
- **Plain `workerd` with a hand-written config:** workerd has no built-in D1. Miniflare
  supplies it on top of workerd.

## Consequences
- **Single node.** The SQLite database lives in one volume, with no replication: back up the
  `urkey-data` volume, which holds ciphertext and metadata only. Losing it is the
  server-deletes-data case (T-7). Devices keep their local copies and encrypted exports.
- **Operator responsibility.** The self-hosting operator replaces Cloudflare for code delivery
  (T-3) and network security. The release hash in `release.json` and Settings › About works
  the same way. Compare it with your own build of the same commit (see below).
- **Miniflare is a beta package** (pinned exactly, `5.20261123.1-beta`, the version the Cloudflare
  Vite plugin uses). Upgrades follow the plugin.
- **The app's API origin is fixed at build time** (CSP `connect-src`). Changing origins means
  `docker compose build`.
- **Release hashes differ between build environments.** The WASM file embeds build paths, so an
  image build does not reproduce the CI hash. A possible fix is `--remap-path-prefix` in every
  build (follow-up).
- **Restoring an older backup needs a resync on every device.** Devices that synced later see a
  rollback warning, but others may see none and miss changes (review N-1). "Accept the server's
  data and resync" (web, `urk sync --resync`) repairs both without losing what a device had
  (sync.md §7.1, owner decision O-14). A protocol-level detection is open (PROGRESS O-15).
- **Test data only until M2.** This rule applies to self-hosting too.
