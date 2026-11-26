import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// `config: true` loads bindings and the entrypoint from cloudflare.config.ts (mode "test").
export default defineConfig({
  plugins: [cloudflareTest({ config: true })],
});
