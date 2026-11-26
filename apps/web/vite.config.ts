/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version ?? "0.0.0"),
    // Set by the release build (scripts/release-hash); "dev" otherwise (R-SEC-11).
    __BUILD_HASH__: JSON.stringify(process.env.URKEY_BUILD_HASH ?? "dev"),
  },
  worker: { format: "es" },
  build: {
    // No source maps in production bundles; reproducible output (R-SEC-11).
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    exclude: ["**/node_modules/**", "src/wasm/**", "e2e/**"],
  },
});
