/// <reference types="vitest/config" />
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflare } from "@cloudflare/vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const API_ORIGIN = process.env["VITE_API_ORIGIN"] ?? "http://localhost:8787";

/**
 * Strict security headers for every static response (R-SEC-10). `connect-src` allows only the
 * configured API; WebAssembly needs 'wasm-unsafe-eval'; nothing third-party is allowed.
 */
export function securityHeaders(apiOrigin: string): string {
  const csp = [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "manifest-src 'self'",
    `connect-src 'self' ${apiOrigin}`,
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types urkey",
  ].join("; ");
  return [
    "/*",
    `  Content-Security-Policy: ${csp}`,
    "  X-Content-Type-Options: nosniff",
    "  Referrer-Policy: no-referrer",
    "  X-Frame-Options: DENY",
    "  Cross-Origin-Opener-Policy: same-origin",
    "  Cross-Origin-Resource-Policy: same-origin",
    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "  Strict-Transport-Security: max-age=63072000; includeSubDomains",
    "/sw.js",
    "  Cache-Control: no-cache",
    "/release.json",
    "  Cache-Control: no-cache",
    "/index.html",
    "  Cache-Control: no-cache",
    "",
  ].join("\n");
}

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

/**
 * After the client build: writes `_headers`, computes the release hash over every served file
 * (sorted paths + SHA-256 of contents, R-SEC-11), and writes `release.json` and a service worker
 * that pins exactly those files (R-SEC-12).
 */
function release(): Plugin {
  let outDir = "dist";
  return {
    name: "urkey-release",
    apply: "build",
    configResolved(c) {
      outDir = c.environments["client"]?.build.outDir ?? c.build.outDir;
    },
    closeBundle: {
      order: "post",
      handler() {
        writeFileSync(join(outDir, "_headers"), securityHeaders(API_ORIGIN));
        const skip = new Set(["sw.js", "release.json", "_headers", ".assetsignore", "wrangler.json"]);
        const served = files(outDir)
          .map((p) => relative(outDir, p).split("\\").join("/"))
          .filter((p) => !skip.has(p) && !p.startsWith(".vite/"))
          .sort();
        const lines = served.map((p) => `${createHash("sha256").update(readFileSync(join(outDir, p))).digest("hex")}  ${p}`);
        const hash = createHash("sha256").update(lines.join("\n")).digest("hex");
        writeFileSync(join(outDir, "release.json"), JSON.stringify({ hash, files: served }, null, 2));
        const sw = readFileSync(join(import.meta.dirname, "src/sw/sw.js"), "utf8")
          .replace("__RELEASE_HASH__", hash)
          .replace("__FILES__", JSON.stringify(served.map((p) => (p === "index.html" ? "/" : `/${p}`))));
        writeFileSync(join(outDir, "sw.js"), sw);
      },
    },
  };
}

const testing = process.env["VITEST"] !== undefined;

export default defineConfig({
  plugins: [react(), ...(testing ? [] : [cloudflare(), release()])],
  define: {
    __APP_VERSION__: JSON.stringify(process.env["npm_package_version"] ?? "0.0.0"),
  },
  worker: { format: "es" },
  resolve: {
    // Radix's scroll lock injects <style> elements, which our CSP blocks; use a CSSOM-only shim.
    alias: { "react-remove-scroll": fileURLToPath(new URL("./src/shims/remove-scroll.tsx", import.meta.url)) },
  },
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
