/** Bindings available to the Worker (see cloudflare.config.ts). */
export interface Env {
  readonly DB: D1Database;
  readonly MIN_CLIENT_VERSION: string;
}
