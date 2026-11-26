import type { Env } from "./env";
import { error, json } from "./http";
import { Router } from "./router";

const API_VERSION = "v1";

const router = new Router().on("GET", "/v1/health", (_request, env) =>
  json({ status: "ok", api: API_VERSION, min_client_version: env.MIN_CLIENT_VERSION }),
);

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await router.handle(request, env);
    } catch {
      // Never echo exception details: they could contain request data (threat model T-20).
      return error(500, "internal_error");
    }
  },
} satisfies ExportedHandler<Env>;
