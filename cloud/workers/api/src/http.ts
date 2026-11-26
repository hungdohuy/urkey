/**
 * Responses. Every response carries the same security headers; error bodies are fixed codes and
 * never echo request data (crypto §10; threat model T-20).
 */

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
};

/** An error that maps to an HTTP status and a fixed code. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: SECURITY_HEADERS });
}

export function empty(status = 204): Response {
  return new Response(null, { status, headers: SECURITY_HEADERS });
}

export function error(status: number, code: string): Response {
  return json({ error: code }, status);
}

/** CORS for the configured web app origin only (api.md; T-26). */
export function withCors(response: Response, request: Request, appOrigin: string): Response {
  const origin = request.headers.get("origin");
  if (origin === null || origin !== appOrigin) return response;
  const r = new Response(response.body, response);
  r.headers.set("access-control-allow-origin", appOrigin);
  r.headers.set("vary", "origin");
  r.headers.set("access-control-allow-headers", "authorization, content-type, urkey-client");
  r.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  r.headers.set("access-control-max-age", "600");
  return r;
}

/** Reads a JSON body with a size cap. */
export async function readJson(request: Request, maxBytes = 1_200_000): Promise<unknown> {
  const len = Number(request.headers.get("content-length") ?? "0");
  if (len > maxBytes) throw new ApiError(413, "too_large");
  const text = await request.text();
  if (text.length > maxBytes) throw new ApiError(413, "too_large");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(400, "invalid_request");
  }
}
