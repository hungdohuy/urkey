import { defineConfig, devices } from "@playwright/test";

// Local servers must not go through an HTTP proxy.
process.env["NO_PROXY"] = ["localhost", "127.0.0.1", process.env["NO_PROXY"] ?? ""].filter(Boolean).join(",");

// End-to-end tests against the real stack: cf dev (API + local D1) and the Vite dev server.
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
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: "pnpm --filter api run e2e:server",
      cwd: "../..",
      url: "http://localhost:8787/v1/health",
      reuseExistingServer: process.env["CI"] === undefined,
      timeout: 120_000,
    },
    {
      command: "pnpm exec vite --port 5173 --strictPort",
      url: "http://localhost:5173",
      reuseExistingServer: process.env["CI"] === undefined,
      timeout: 120_000,
    },
  ],
});
