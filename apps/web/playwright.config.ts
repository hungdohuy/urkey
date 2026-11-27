import { defineConfig, devices } from "@playwright/test";

// Local servers must not go through an HTTP proxy.
process.env["NO_PROXY"] = ["localhost", "127.0.0.1", process.env["NO_PROXY"] ?? ""].filter(Boolean).join(",");

// End-to-end tests against the real stack: cf dev (API + local D1) and the Vite dev server.
// URKEY_E2E_APP_URL runs every test against an already running deployment instead (e.g. the
// Docker Compose stack: URKEY_E2E_APP_URL=http://localhost:8080); no servers are started then.
const external = process.env["URKEY_E2E_APP_URL"];

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "off",
    permissions: ["clipboard-read", "clipboard-write"],
  },
  projects: [
    { name: "dev", testMatch: /(vault|canary|fault|reregister)\.spec\.ts/, use: { ...devices["Desktop Chrome"], baseURL: external ?? "http://localhost:5173" } },
    // The production build on the real asset Worker (workerd): CSP, Trusted Types, service worker.
    { name: "production", testMatch: /production\.spec\.ts/, use: { ...devices["Desktop Chrome"], baseURL: external ?? "http://localhost:4173" } },
  ],
  // SIGTERM, not Playwright's default SIGKILL: `cf dev` runs its server in a new session, so a
  // SIGKILL to the process group orphans it and Playwright then waits forever for its output
  // to close (the "stuck after the last test" hang). SIGTERM lets cf dev stop its own child.
  webServer: external !== undefined ? [] : [
    {
      command: "pnpm --filter api run e2e:server",
      cwd: "../..",
      url: "http://localhost:8787/v1/health",
      reuseExistingServer: process.env["CI"] === undefined,
      gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
      timeout: 120_000,
    },
    {
      command: "pnpm exec vite build && pnpm exec vite preview --port 4173 --strictPort",
      url: "http://localhost:4173",
      reuseExistingServer: process.env["CI"] === undefined,
      gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
      timeout: 180_000,
    },
    {
      command: "pnpm exec vite --port 5173 --strictPort",
      url: "http://localhost:5173",
      reuseExistingServer: process.env["CI"] === undefined,
      gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
      timeout: 120_000,
    },
  ],
});
