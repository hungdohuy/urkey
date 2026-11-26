/**
 * Response helpers. Every response carries the same security headers, and bodies are
 * fixed, non-secret JSON (cryptographic-design.md §10; threat model T-20).
 */

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
};

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: SECURITY_HEADERS });
}

export function error(status: number, code: string): Response {
  return json({ error: code }, status);
}
