/** Bindings available to the Worker (see cloudflare.config.ts). */
export interface Env {
  readonly DB: D1Database;
  readonly MIN_CLIENT_VERSION: string;
  /** Exact origin clients sign in login/recovery messages (crypto §7.4). */
  readonly API_ORIGIN: string;
  /** The web app origin allowed by CORS. */
  readonly APP_ORIGIN: string;
  /** HMAC key for deterministic fake prelogin answers (crypto §7.4 step 1). */
  readonly PRELOGIN_SECRET: string;
}
