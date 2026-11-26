import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig } from "vite";

// The Cloudflare Vite plugin 2.0 reads cloudflare.config.ts; `cf dev` / `cf build` run Vite.
export default defineConfig({
  plugins: [cloudflare()],
});
