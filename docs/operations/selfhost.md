# Self-hosting with Docker Compose

An alternative to Cloudflare (`deploy.md`): the same API and web app on your own machine or
server. Design and trade-offs: [ADR 0018](../decisions/0018-self-hosting-with-docker-compose.md).
**Test data only until M2.**

## What runs

| Service | Image target | Role | Published |
|---------|--------------|------|-----------|
| `web` | Caddy | Serves the app with the production security headers; the only way in to the API (`/v1/*` only) | `127.0.0.1:8080` (app), `127.0.0.1:8787` (API) |
| `api` | Node + workerd (Miniflare) | The unchanged Worker bundle; D1 as SQLite in the `urkey-data` volume | not published |

Needs Docker with Compose v2. The first build compiles the WASM core and the wasm-pack tools,
which takes several minutes.

## On this computer only (default)

```bash
docker compose up -d --build
```

Then open http://localhost:8080. Check the API at http://localhost:8787/v1/health.

The CLI works against it too:

```bash
./scripts/dev.sh cli init --server http://localhost:8787
```

## From other devices (HTTPS)

Phones and other computers need HTTPS: the PWA, WebCrypto and the service worker require a
secure context, and only `localhost` counts as one without TLS.

1. Pick two hostnames that point to the server, e.g. `app.home.lan` and `api.home.lan`.
2. Create `.env`:
   ```bash
   cp deploy/selfhost/selfhost.env.example .env
   ```
   Then set:
   ```
   URKEY_APP_ORIGIN=https://app.home.lan
   URKEY_API_ORIGIN=https://api.home.lan
   URKEY_TLS_MODE=internal        # LAN names: Caddy's own CA. Public names: auto (Let's Encrypt)
   ```
3. Start with the TLS override, which publishes ports 80 and 443:
   ```bash
   docker compose -f compose.yaml -f deploy/selfhost/compose.tls.yaml up -d --build
   ```
4. With `internal`, install Caddy's root certificate on each device. Export it with:
   ```bash
   docker compose cp web:/data/caddy/pki/authorities/local/root.crt ./urkey-local-root.crt
   ```
   On iPhone, AirDrop or mail it to yourself, install the profile, then enable it under
   Settings › General › About › Certificate Trust Settings.

Changing an origin needs a rebuild (`--build`), because the app's CSP names the API origin.

## Operating it

| Task | Command |
|------|---------|
| Status and health | `docker compose ps` |
| Logs (no secrets are logged) | `docker compose logs -f api web` |
| Stop / start | `docker compose stop` / `docker compose start` |
| Update to a new commit | `git pull && docker compose up -d --build` (migrations run on start) |
| Release hash of the running app | `docker compose exec web cat /srv/release.json` (compare with Settings › About and the published hash) |
| Remove everything, data included | `docker compose down -v` |

### Backup and restore

The volume is named `urkey_urkey-data`. Stop the API first so the SQLite files are consistent.
Run these from the directory where the archive should go. The archive is created with mode
0600 because it contains the prelogin secret.

```bash
docker compose stop api
docker run --rm -v urkey_urkey-data:/data -v "$PWD":/backup busybox:1.37.0 sh -c 'umask 077 && tar czf /backup/urkey-data.tgz -C /data .'
docker compose start api
```

To restore:

```bash
docker compose stop api
docker run --rm -v urkey_urkey-data:/data -v "$PWD":/backup busybox:1.37.0 sh -c 'rm -rf /data/* && tar xzf /backup/urkey-data.tgz -C /data'
docker compose start api
```

**After restoring an older backup, every device must resync.** Devices that synced after the
backup see "The server returned older data than this device has seen" and stop syncing. That is
the rollback protection (threat model T-9) working. Other devices may see **no warning at all**
if enough new activity has raised the server's counter back, and then they silently miss changes
(zero-knowledge review N-1). So after any restore, on **each** device:
- web: Settings › Backup › **Resync from the server** (or "accept its data and resync" in the
  warning);
- CLI: `urk sync --resync`.

**Devices that joined after the backup are unknown to the restored server** and cannot sync
until they sign in again. Their local data is kept:
- web: a banner says "The server doesn't recognise this device". Click **Sign this device in
  again**. It signs in with the device's own key and your unlocked session (no password or Secret
  Key is typed again), then resyncs as below;
- CLI: run `urk login` again, then `urk sync --resync`.

Resyncing pulls everything again and sends back anything newer that only that device has: items the
backup lost, and edits newer than the backup's versions. Where the restored server holds
different content at the same or a newer revision, both are kept (the device's version appears as
"… (this device's copy)"). Nothing is deleted. Details: sync.md §7.1. The whole procedure is
tested by `tests/integration/selfhost_restore.sh`.

The `urkey-data` volume holds:
- the database, which contains only ciphertext, public keys and metadata;
- the prelogin secret.

A backup is as sensitive as a copy of the server: no vault can be read without the
password **and** Secret Key. It still reveals emails and other metadata, so keep it private.

## Security notes

- Only Caddy is reachable. The API container runs as a non-root user with a read-only root
  filesystem and no capabilities, and accepts only `/v1/*`.
- Miniflare's development features are off: the Local Explorer, request-trace capture,
  telemetry and calls to Cloudflare.
- Rate limits use the real client address. Caddy replaces any `X-Forwarded-For` a client
  sends.
- You are now the code-delivery path (threat model T-3). Build from a commit you trust, and
  compare the release hash. The hash depends on the build environment: Rust embeds build paths
  in the WASM file, so an image build gives a different hash than CI or a local `pnpm` build of
  the same commit. Compare it with a build of your own from the same commit and Dockerfile.
- There's no edge DDoS protection. Keep it on localhost or a private network unless you know
  you need public access.

## Behind a TLS-intercepting proxy (building only)

If your network intercepts TLS, the build needs that proxy's CA. Add a build secret named `ca`,
for example with a small override file:

```yaml
services:
  api: { build: { secrets: [ca] } }
  web: { build: { secrets: [ca] } }
secrets:
  ca: { file: /path/to/proxy-ca.pem }
```

The secret is used only during downloads and is not stored in the images.
