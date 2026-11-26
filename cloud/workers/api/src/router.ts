/**
 * Minimal hand-written router (D-9, ADR 0010): exact method + path matching.
 */
import type { Env } from "./env";
import { error } from "./http";

export type Handler = (request: Request, env: Env, now: number) => Promise<Response> | Response;

export class Router {
  readonly #routes = new Map<string, Map<string, Handler>>();

  on(method: string, path: string, handler: Handler): this {
    let byMethod = this.#routes.get(path);
    if (byMethod === undefined) {
      byMethod = new Map();
      this.#routes.set(path, byMethod);
    }
    byMethod.set(method.toUpperCase(), handler);
    return this;
  }

  /** Methods registered for a path (for CORS preflight and 405). */
  methods(pathname: string): string[] {
    return [...(this.#routes.get(pathname)?.keys() ?? [])];
  }

  async handle(request: Request, env: Env, now: number): Promise<Response> {
    const { pathname } = new URL(request.url);
    const byMethod = this.#routes.get(pathname);
    if (byMethod === undefined) {
      return error(404, "not_found");
    }
    const handler = byMethod.get(request.method.toUpperCase());
    if (handler === undefined) {
      const response = error(405, "method_not_allowed");
      response.headers.set("allow", [...byMethod.keys()].join(", "));
      return response;
    }
    return handler(request, env, now);
  }
}
