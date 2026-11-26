# 0014. Use the `cf` CLI instead of Wrangler

- Status: Accepted
- Date: 2026-11-26
- Decision: D-19 (owner request)
- Requirements: —

## Context
The owner asked to use Cloudflare's `cf` CLI rather than Wrangler. `cf` reads a typed
`cloudflare.config.ts`, covers the whole Cloudflare API, and hands building to either Wrangler or
Vite. Choosing the Wrangler bundler would keep Wrangler as a project dependency.

## Decision
- The API Worker is configured in `cloud/workers/api/cloudflare.config.ts` (migrated from
  `wrangler.jsonc` with `cf migrate --bundler vite`); the Wrangler config file and dependency are removed.
- Build and dev go through the **Vite bundler**: `vite` + `@cloudflare/vite-plugin` 2.0 (which does
  not depend on Wrangler). `cf dev`, `cf build`, `cf deploy`.
- Tests use `@cloudflare/vitest-plugin` with `cloudflareTest({ config: true })`, which loads
  `cloudflare.config.ts` in mode `test`.
- D1 migrations stay in `migrations/` and are applied with `cf d1 migrations apply <id> --dir migrations`.
  Local commands need a database id, so non-production modes use a fixed local-only id
  (`LOCAL_D1_ID`); production omits the id until the database is created (roadmap P7).
- `cf` is pinned (`1.0.0-rc.6`) as a dev dependency of the Worker package. Telemetry is disabled
  with `CF_SEND_TELEMETRY=false`.
- Commands `cf` does not support yet (live logs, single secrets) are run with `npx wrangler …`
  only when needed, without adding Wrangler to the project.

## Alternatives considered
- Keep Wrangler: mature and documented, but not what the owner wants.
- `cf` with the Wrangler bundler: smallest migration, but keeps Wrangler installed and uses the
  experimental `wrangler.config.ts`.

## Consequences
- `cf` 1.0 is a release candidate; some less common commands may change. Pin and upgrade deliberately.
- Product docs often show Wrangler commands; translate them with `cf cli search` instead of running them.
- The Vite bundler matches the web app's build tool, so the repo has one bundler.
