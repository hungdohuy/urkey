import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { encode } from "../src/b64";
import { random } from "../src/crypto";
import { cleanup } from "../src/index";
import { api, createAccount, mutation, pull } from "./helpers";

const push = (token: string, mutations: unknown[]) => api("/v1/sync/push", { body: { mutations }, token });

describe("sync", () => {
  it("applies creates and updates and exposes them in the feed", async () => {
    const ctx = await createAccount();
    const item = random(16);
    const m1 = mutation(ctx, item, 0);
    const r1 = await push(ctx.token, [m1]);
    expect(r1.body["results"][0]).toEqual({ status: "applied", seq: 1 });
    const m2 = mutation(ctx, item, 1);
    expect((await push(ctx.token, [m2])).body["results"][0]).toEqual({ status: "applied", seq: 2 });
    const feed = await pull(ctx.token);
    expect(feed.body["vault_seq"]).toBe(2);
    expect(feed.body["changes"]).toHaveLength(1); // latest revision only
    expect(feed.body["changes"][0].item.revision).toBe(2);
    expect(feed.body["changes"][0].item.body).toBe(m2.body);
  });

  it("is idempotent and refuses a reused mutation id with different content", async () => {
    const ctx = await createAccount();
    const m = mutation(ctx, random(16), 0);
    await push(ctx.token, [m]);
    expect((await push(ctx.token, [m])).body["results"][0]).toEqual({ status: "duplicate", seq: 1 });
    const altered = { ...m, body: mutation(ctx, random(16), 0).body };
    expect((await push(ctx.token, [altered])).body["results"][0].status).toBe("invalid");
  });

  it("reports conflicts with the current record", async () => {
    const ctx = await createAccount();
    const item = random(16);
    await push(ctx.token, [mutation(ctx, item, 0)]);
    await push(ctx.token, [mutation(ctx, item, 1)]);
    const r = await push(ctx.token, [mutation(ctx, item, 1)]);
    expect(r.body["results"][0].status).toBe("conflict");
    expect(r.body["results"][0].current.revision).toBe(2);
    expect((await push(ctx.token, [mutation(ctx, item, 0)])).body["results"][0].status).toBe("conflict");
  });

  it("refuses malformed mutations without echoing them", async () => {
    const ctx = await createAccount();
    const item = random(16);
    const wrongRef = { ...mutation(ctx, item, 0), body: mutation(ctx, random(16), 0).body };
    const wrongRev = { ...mutation(ctx, item, 0), revision: 5 };
    const r = await push(ctx.token, [wrongRef, wrongRev, { junk: true }]);
    expect(r.body["results"].map((x: any) => x.status)).toEqual(["invalid", "invalid", "invalid"]);
    expect(JSON.stringify(r.body)).not.toContain(wrongRef.body);
  });

  it("reports keyset_changed for a stale vault key", async () => {
    const ctx = await createAccount();
    const r = await push(ctx.token, [mutation(ctx, random(16), 0, { vmkId: random(16) })]);
    // A dek_wrap keyed to another VMK is a well-formed container; the account's VMK differs.
    expect(r.body["results"][0].status).toBe("keyset_changed");
  });

  it("parallel pushes on the same base: exactly one wins, feed positions stay unique (D-15)", async () => {
    const ctx = await createAccount();
    const item = random(16);
    await push(ctx.token, [mutation(ctx, item, 0)]);
    const racers = await Promise.all(Array.from({ length: 8 }, () => push(ctx.token, [mutation(ctx, item, 1)])));
    const statuses = racers.map((r) => r.body["results"][0].status);
    expect(statuses.filter((s) => s === "applied")).toHaveLength(1);
    expect(statuses.filter((s) => s === "conflict")).toHaveLength(7);
    // Independent items in parallel all apply with distinct, gap-free seqs.
    const many = await Promise.all(Array.from({ length: 10 }, () => push(ctx.token, [mutation(ctx, random(16), 0)])));
    const seqs = many.map((r) => r.body["results"][0].seq as number).sort((a, b) => a - b);
    expect(new Set(seqs).size).toBe(10);
    expect(seqs[9]! - seqs[0]!).toBe(9);
    const feed = await pull(ctx.token);
    const feedSeqs = feed.body["changes"].map((c: any) => c.seq);
    expect(feedSeqs).toEqual([...feedSeqs].sort((a: number, b: number) => a - b));
  });

  it("pages the feed", async () => {
    const ctx = await createAccount();
    for (let i = 0; i < 5; i++) await push(ctx.token, [mutation(ctx, random(16), 0)]);
    const p1 = await pull(ctx.token, 0, 2);
    expect(p1.body["changes"]).toHaveLength(2);
    expect(p1.body["has_more"]).toBe(true);
    const p2 = await pull(ctx.token, p1.body["next"], 10);
    expect(p2.body["changes"]).toHaveLength(3);
    expect(p2.body["has_more"]).toBe(false);
  });

  it("purges old tombstones and answers 410 to stale cursors, but allows a full resync", async () => {
    const ctx = await createAccount();
    const item = random(16);
    await push(ctx.token, [mutation(ctx, item, 0)]);
    await push(ctx.token, [mutation(ctx, item, 1, { deleted: true })]);
    await push(ctx.token, [mutation(ctx, random(16), 0)]);
    // Age the tombstone past the 90-day retention, then run the scheduled cleanup.
    await env.DB.prepare("UPDATE items SET updated_at = updated_at - ? WHERE deleted = 1").bind(91 * 24 * 60 * 60 * 1000).run();
    await cleanup(env, Date.now());
    expect((await pull(ctx.token, 1)).status).toBe(410);
    const full = await pull(ctx.token, 0);
    expect(full.status).toBe(200);
    expect(full.body["changes"].filter((c: any) => c.type === "item")).toHaveLength(1);
    expect(full.body["changes"].some((c: any) => c.type === "item" && c.item.item_id === encode(item))).toBe(false);
  });
});
