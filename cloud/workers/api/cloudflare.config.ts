// urkey API Worker (docs/architecture/overview.md §8, api.md). Stores ciphertext only.
// Managed with the `cf` CLI. D1 migrations live in ./migrations and are applied with
// `cf d1 migrations apply` (package.json `migrate:local`).
import { bindings, defineConfig, triggers } from "cf/config";

/**
 * Fixed id for the local D1 simulation used by `cf dev`, Vitest and `migrate:local`.
 * It never reaches Cloudflare: in `production` mode the id is omitted until the real
 * database is created at deployment time (roadmap P7).
 */
export const LOCAL_D1_ID = "00000000-0000-4000-8000-000000000001";

export default defineConfig(({ mode }) => {
  const production = mode === "production";
  return {
    worker: {
      name: "urkey-api",
      compatibilityDate: "2026-11-01",
      entrypoint: "src/index.ts",
      observability: {
        enabled: true,
      },
      triggers: [triggers.scheduled({ schedule: "17 4 * * *" })],
      env: {
        MIN_CLIENT_VERSION: bindings.text("0.0.0"),
        // Set per deployment (P7). Local development and tests use these values.
        API_ORIGIN: bindings.text(production ? "https://api.urkey.example" : "http://localhost:8787"),
        APP_ORIGIN: bindings.text(production ? "https://app.urkey.example" : "http://localhost:5173"),
        PRELOGIN_SECRET: bindings.secret(),
        DB: bindings.d1(production ? { name: "urkey" } : { name: "urkey", id: LOCAL_D1_ID }),
      },
    },
  };
});
