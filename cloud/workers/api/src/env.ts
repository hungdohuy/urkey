/** Bindings available to the Worker (see wrangler.jsonc). */
export interface Env {
  readonly DB: D1Database;
  readonly MIN_CLIENT_VERSION: string;
}
