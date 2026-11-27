// Self-hosted urkey API (ADR 0018). Runs the same built Worker bundle (`cf build`) in workerd
// through Miniflare. D1 is persisted as SQLite in $URKEY_DATA. The Vite dev and preview
// servers are not used: no /__debug, and requests to /cdn-cgi/* are refused here as well as at
// the proxy.
//
// Environment:
//   URKEY_API_ORIGIN  exact public origin of this API (signed in login messages), e.g. https://api.example.lan
//   URKEY_APP_ORIGIN  exact origin of the web app (the only CORS origin)
//   URKEY_DATA        data directory (default /data): D1 database and the prelogin secret
//   PORT              listen port (default 8787), HOST (default 0.0.0.0)
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, chmodSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const apiDir = join(here, "..");
const env = (k, d) => {
  const v = process.env[k];
  if (v === undefined || v === "") {
    if (d === undefined) throw new Error(`${k} must be set`);
    return d;
  }
  return v;
};

const API_ORIGIN = env("URKEY_API_ORIGIN");
const APP_ORIGIN = env("URKEY_APP_ORIGIN");
const DATA = env("URKEY_DATA", "/data");
const PORT = Number(env("PORT", "8787"));
const HOST = env("HOST", "0.0.0.0");
for (const [k, v] of [["URKEY_API_ORIGIN", API_ORIGIN], ["URKEY_APP_ORIGIN", APP_ORIGIN]]) {
  const u = new URL(v);
  if (u.origin !== v) throw new Error(`${k} must be an origin like https://host[:port], got ${v}`);
}

// The prelogin secret (fake prelogin responses, threat model T-17) is generated once and kept
// in the data volume with mode 0600. It is never printed.
mkdirSync(DATA, { recursive: true, mode: 0o700 });
const secretFile = join(DATA, "prelogin_secret");
if (!existsSync(secretFile)) writeFileSync(secretFile, randomBytes(32).toString("hex"), { mode: 0o600 });
chmodSync(secretFile, 0o600);
const PRELOGIN_SECRET = readFileSync(secretFile, "utf8").trim();

const config = JSON.parse(readFileSync(join(apiDir, ".cloudflare/output/v1/workers/default/worker.config.json"), "utf8"));
const options = convertV4MiniflareOptions({
  // Internal only; the public listener below forwards to it.
  host: "127.0.0.1",
  port: 0,
  resourcePersistencePath: join(DATA, "state"),
  // Scratch files go to the tmpfs, so the container can run with a read-only root filesystem.
  resourceTmpPath: join(tmpdir(), "urkey-miniflare"),
  name: config.name,
  modules: true,
  scriptPath: join(apiDir, ".cloudflare/output/v1/workers/default/bundle/index.js"),
  compatibilityDate: config.compatibilityDate,
  compatibilityFlags: config.compatibilityFlags ?? [],
  d1Databases: { DB: "urkey" },
  bindings: {
    API_ORIGIN,
    APP_ORIGIN,
    MIN_CLIENT_VERSION: config.env?.MIN_CLIENT_VERSION?.value ?? "0.0.0",
    PRELOGIN_SECRET,
  },
  log: new Log(LogLevel.WARN),
});
// Development tooling stays off: no Local Explorer (it could read D1), no captured request
// traces (they could hold session tokens), no telemetry, no dev registry, no calls to Cloudflare.
Object.assign(options, {
  unsafeLocalExplorer: false,
  unsafeObservability: false,
  enableDevRegistry: false,
  telemetry: { enabled: false },
  logRequests: false,
  // Never contact Cloudflare: use a fixed placeholder instead of fetching Request.cf.
  cf: false,
});
const mf = new Miniflare(options);
const internal = await mf.ready;

// Migrations: apply each file in migrations/ once, in order, recorded in d1_migrations.
const db = await mf.getD1Database("DB");
await db.prepare("CREATE TABLE IF NOT EXISTS d1_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)").run();
for (const file of readdirSync(join(apiDir, "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
  if (await db.prepare("SELECT 1 FROM d1_migrations WHERE name = ?").bind(file).first()) continue;
  const sql = readFileSync(join(apiDir, "migrations", file), "utf8")
    .split("\n")
    .filter((l) => !l.trim().startsWith("--"))
    .join("\n");
  const statements = sql.split(/;\s*(?:\n|$)/).map((s) => s.trim()).filter(Boolean);
  await db.batch([...statements.map((s) => db.prepare(s)), db.prepare("INSERT INTO d1_migrations (name, applied_at) VALUES (?, ?)").bind(file, Date.now())]);
  process.stdout.write(`applied migration ${file}\n`);
}

// Retention job (data-model §3): at start and every 6 hours. It is idempotent.
const worker = await mf.getWorker();
const cleanup = () => worker.scheduled({ cron: "17 4 * * *" }).catch(() => process.stderr.write("cleanup failed\n"));
await cleanup();
setInterval(cleanup, 6 * 60 * 60 * 1000).unref();

// Public listener: only /v1/* reaches the Worker. Everything else, /cdn-cgi/* included, is 404.
// CF-Connecting-IP is set from the proxy's X-Forwarded-For (TRUST_PROXY=1) or from the peer
// address. A client-supplied value is always replaced, so rate limits cannot be dodged by
// sending one.
const TRUST_PROXY = env("TRUST_PROXY", "0") === "1";
createServer((req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  if (!path.startsWith("/v1/")) {
    res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not_found"}');
    return;
  }
  const fwd = TRUST_PROXY ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() : "";
  const ip = fwd !== "" ? fwd : (req.socket.remoteAddress ?? "unknown");
  const headers = { ...req.headers, host: internal.host, "cf-connecting-ip": ip };
  delete headers["x-forwarded-for"];
  const up = httpRequest({ hostname: internal.hostname, port: internal.port, method: req.method, path: req.url, headers }, (r) => {
    res.writeHead(r.statusCode ?? 502, r.headers);
    r.pipe(res);
  });
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
    res.end('{"error":"internal_error"}');
  });
  req.pipe(up);
}).listen(PORT, HOST, () => process.stdout.write(`urkey API on ${HOST}:${PORT} for ${API_ORIGIN} (app ${APP_ORIGIN})\n`));

const stop = async () => {
  await mf.dispose();
  process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
