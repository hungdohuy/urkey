// urkey web app: an assets-only Worker on its own hostname, separate from the API (R-SEC-13,
// ADR 0002). Security headers come from the generated `_headers` file (vite.config.ts).
import { defineConfig } from "cf/config";

export default defineConfig({
  worker: {
    name: "urkey-app",
    compatibilityDate: "2026-11-01",
    assets: {
      notFoundHandling: "single-page-application",
      htmlHandling: "auto-trailing-slash",
    },
  },
});
