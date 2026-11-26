import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const BASE = "http://localhost:8787";

describe("GET /v1/health", () => {
  it("returns ok with the API version", async () => {
    const response = await exports.default.fetch(`${BASE}/v1/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok", api: "v1", min_client_version: "0.0.0" });
  });

  it("sends security headers and is never cached", async () => {
    const response = await exports.default.fetch(`${BASE}/v1/health`);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  });
});

describe("routing", () => {
  it("returns a fixed 404 body for unknown paths", async () => {
    const response = await exports.default.fetch(`${BASE}/v1/nope?secret=abc`);
    expect(response.status).toBe(404);
    const body = await response.text();
    expect(body).toBe('{"error":"not_found"}');
  });

  it("returns 405 with Allow for a wrong method", async () => {
    const response = await exports.default.fetch(`${BASE}/v1/health`, { method: "POST" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
  });
});
