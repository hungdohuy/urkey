import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// `config: true` loads bindings and the entrypoint from cloudflare.config.ts (mode "test").
export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      config: true,
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations(path.join(import.meta.dirname, "migrations")),
          PRELOGIN_SECRET: "test-only-prelogin-secret",
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/apply-migrations.ts"],
  },
});
