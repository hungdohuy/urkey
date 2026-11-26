# Deploying urkey to Cloudflare (owner runbook)

Status: **prepared and dry-run only.** Nothing has been deployed. Deploying needs the owner's
Cloudflare account, a domain and an API token (PROGRESS.md O-8). Real credentials must not be
stored before M2.

CI runs `cf deploy --dry-run` for both Workers on every push; no credentials are needed for that.

## What gets deployed

| Worker | Directory | Host (example) | Contents |
|--------|-----------|----------------|----------|
| `urkey-api` | `cloud/workers/api` | `api.<your-domain>` | API + D1 (`urkey`), daily retention job (04:17 UTC) |
| `urkey-app` | `apps/web` | `app.<your-domain>` | Static assets only; `_headers` with strict CSP and Trusted Types, `sw.js`, `release.json` |

Separate hosts are required (R-SEC-13). The app's CSP `connect-src` allows only the API origin.

## One-time setup

1. **Domain.** Pick two hostnames on a zone in your Cloudflare account, e.g.
   `app.example.com` and `api.example.com`.
2. **Origins.** Edit `cloud/workers/api/cloudflare.config.ts` and replace the placeholder
   production origins `https://api.urkey.example` and `https://app.urkey.example` with the real
   ones. Login and recovery messages sign `API_ORIGIN`, so it must be the exact origin clients
   use. Then attach each Worker to its hostname as a custom domain. The Cloudflare dashboard (Workers › Settings › Domains) is the simplest way; for the CLI, run `cf cli search "attach a custom domain to a worker"`.
3. **API token.** Create a token scoped to the account with *Workers Scripts: Edit*,
   *D1: Edit* and, if routes are used, *Zone: Workers Routes: Edit*. Export it as
   `CLOUDFLARE_API_TOKEN` in your shell only; never commit it.
4. **Database.**
   ```bash
   cd cloud/workers/api
   CF_SEND_TELEMETRY=false pnpm exec cf d1 create urkey
   ```
   Put the returned id in `cloudflare.config.ts` (production `DB` binding), then apply the
   migrations remotely:
   ```bash
   CF_SEND_TELEMETRY=false pnpm exec cf d1 migrations apply <database id>
   ```
   (Without `--local`, `cf` targets the real database. Read `--help` first.)
5. **Prelogin secret.** Set a random secret of 32 bytes or more (fake prelogin responses, T-11):
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # copy the output
   CF_SEND_TELEMETRY=false pnpm exec cf workers secrets update PRELOGIN_SECRET
   ```
   (`cf workers secrets update --help` shows how it takes the value. Never put the value in a
   file in the repository.)

## Each release

```bash
# 1. API
(cd cloud/workers/api && CF_SEND_TELEMETRY=false pnpm exec cf deploy --dry-run && CF_SEND_TELEMETRY=false pnpm exec cf deploy)
# 2. App, built against the real API origin
pnpm wasm
(cd apps/web && VITE_API_ORIGIN=https://api.example.com CF_SEND_TELEMETRY=false pnpm exec cf deploy)
```

After deploying the app:
- Publish the `hash` from `apps/web/.cloudflare/output/v1/workers/default/assets/release.json`,
  e.g. in the release notes of the commit (R-SEC-11). Anyone can rebuild the same commit and
  compare it. Two builds of the same commit give the same hash (checked in CI).
- On each device, Settings › About shows the installed release hash. A new release waits behind
  the "Update now" banner until you approve it (R-SEC-12). Before approving, compare the hash
  with the one you published.
- Check `https://api.example.com/v1/health` and the response headers of the app (`cf` does not
  rewrite `_headers`).

## Rollback

Redeploy the previous commit with the same commands. Clients pinned to a release keep running
it until the user approves the change. The database schema is forward-only. Never roll back a
migration on a database with data; write a new migration instead.
