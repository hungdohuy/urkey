// urkey API Worker (docs/architecture/overview.md §8). Stores ciphertext only.
// Managed with the `cf` CLI. D1 migrations live in ./migrations and are applied with
// `cf d1 migrations apply` (package.json `migrate:local`).
import { bindings, defineConfig } from "cf/config";

/**
 * Fixed id for the local D1 simulation used by `cf dev`, Vitest and `migrate:local`.
 * It never reaches Cloudflare: in `production` mode the id is omitted until the real
 * database is created at deployment time (roadmap P7).
 */
export const LOCAL_D1_ID = "00000000-0000-4000-8000-000000000001";

export default defineConfig(({ mode }) => ({
  worker: {
    name: "urkey-api",
    compatibilityDate: "2026-11-01",
    entrypoint: "src/index.ts",
    observability: {
      enabled: true,
    },
    env: {
      MIN_CLIENT_VERSION: bindings.text("0.0.0"),
      DB: bindings.d1(mode === "production" ? { name: "urkey" } : { name: "urkey", id: LOCAL_D1_ID }),
    },
  },
}));
