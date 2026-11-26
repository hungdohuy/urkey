/** Change feed and push (sync.md §3; api.md atomicity). */
import { blob, encode, equal } from "../b64";
import { rateLimit, requireSession } from "../auth";
import { containerOk, Kind, sha256 } from "../crypto";
import { loadAccount, MAX_ITEMS } from "../db";
import type { Env } from "../env";
import { ApiError, json, readJson } from "../http";
import { arr, bool, bytes, int, obj } from "../validate";

const MINUTE = 60_000;

interface ItemRow {
  item_id: unknown;
  revision: number;
  seq: number;
  vmk_id: unknown;
  dek_wrap: unknown;
  body: unknown;
  deleted: number;
  updated_at: number;
  updated_by: unknown;
}

function wireRecord(r: ItemRow) {
  return {
    item_id: encode(blob(r.item_id)),
    revision: r.revision,
    seq: r.seq,
    vmk_id: encode(blob(r.vmk_id)),
    dek_wrap: encode(blob(r.dek_wrap)),
    body: encode(blob(r.body)),
    deleted: r.deleted === 1,
    updated_at: r.updated_at,
    updated_by: encode(blob(r.updated_by)),
  };
}

export async function changes(request: Request, env: Env, now: number): Promise<Response> {
  const s = await requireSession(request, env, ["full"], now);
  await rateLimit(env, `pull:${encode(s.deviceId)}`, 120, MINUTE, now);
  const url = new URL(request.url);
  const since = Number(url.searchParams.get("since") ?? "0");
  const limit = Math.min(Number(url.searchParams.get("limit") ?? "500"), 500);
  if (!Number.isSafeInteger(since) || since < 0 || !Number.isSafeInteger(limit) || limit < 1) throw new ApiError(400, "invalid_request");
  const a = await loadAccount(env, s.accountId);
  if (a === null) throw new ApiError(401, "unauthorized");
  if (since > 0 && since < a.tombstoneHorizon) throw new ApiError(410, "resync_required");
  const [items, events] = await Promise.all([
    env.DB.prepare("SELECT * FROM items WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?").bind(a.accountId, since, limit + 1).all<ItemRow>(),
    env.DB.prepare("SELECT seq, kind, device_id, created_at FROM security_events WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?")
      .bind(a.accountId, since, limit + 1)
      .all<{ seq: number; kind: string; device_id: unknown; created_at: number }>(),
  ]);
  const merged = [
    ...items.results.map((r) => ({ type: "item" as const, seq: r.seq, item: wireRecord(r) })),
    ...events.results.map((e) => ({
      type: "event" as const,
      seq: e.seq,
      event: { kind: e.kind, device_id: e.device_id === null ? null : encode(blob(e.device_id)), created_at: e.created_at },
    })),
  ].sort((x, y) => x.seq - y.seq);
  const page = merged.slice(0, limit);
  return json({
    vault_seq: a.vaultSeq,
    keyset_version: a.keysetVersion,
    vmk_id: encode(a.vmkId),
    changes: page,
    next: page.at(-1)?.seq ?? since,
    has_more: merged.length > limit,
  });
}

interface Mutation {
  mutationId: Uint8Array;
  itemId: Uint8Array;
  base: number;
  revision: number;
  vmkId: Uint8Array;
  dekWrap: Uint8Array;
  body: Uint8Array;
  deleted: boolean;
  hash: Uint8Array;
}

async function parseMutation(x: unknown): Promise<Mutation | null> {
  try {
    const o = obj(x);
    const m = {
      mutationId: bytes(o, "mutation_id", 16),
      itemId: bytes(o, "item_id", 16),
      base: int(o, "base_revision"),
      revision: int(o, "revision", 1),
      vmkId: bytes(o, "vmk_id", 16),
      dekWrap: bytes(o, "dek_wrap", undefined, 1024),
      body: bytes(o, "body", undefined, 1_200_000),
      deleted: bool(o, "deleted"),
    };
    const canonical = new TextEncoder().encode(
      JSON.stringify([encode(m.mutationId), encode(m.itemId), m.base, m.revision, encode(m.vmkId), encode(m.dekWrap), encode(m.body), m.deleted]),
    );
    return { ...m, hash: await sha256(canonical) };
  } catch {
    return null;
  }
}

async function applyOne(env: Env, accountId: Uint8Array, deviceId: Uint8Array, m: Mutation, now: number): Promise<unknown> {
  if (m.revision !== m.base + 1) return { status: "invalid", code: "bad_revision" };
  if (!containerOk(m.dekWrap, [Kind.DekWrap], m.vmkId) || !containerOk(m.body, [Kind.ItemPayload, Kind.Tombstone], m.itemId)) {
    return { status: "invalid", code: "bad_container" };
  }
  const prior = await env.DB.prepare("SELECT request_hash, result FROM mutations WHERE account_id = ? AND mutation_id = ?")
    .bind(accountId, m.mutationId)
    .first<{ request_hash: unknown; result: string }>();
  if (prior !== null) {
    if (!equal(blob(prior.request_hash), m.hash)) return { status: "invalid", code: "mutation_id_reused" };
    const r = JSON.parse(prior.result) as { seq: number };
    return { status: "duplicate", seq: r.seq };
  }
  if (m.base === 0) {
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM items WHERE account_id = ?").bind(accountId).first<{ n: number }>();
    if ((n?.n ?? 0) >= MAX_ITEMS) return { status: "invalid", code: "limit_reached" };
  }
  // One guard shared by every statement in the batch: all apply or none (api.md, D-15).
  const guard =
    m.base === 0
      ? "NOT EXISTS (SELECT 1 FROM items WHERE account_id = ?1 AND item_id = ?2)"
      : "(SELECT revision FROM items WHERE account_id = ?1 AND item_id = ?2) = ?3";
  const vmkGuard = "(SELECT vmk_id FROM accounts WHERE account_id = ?1) = ?4";
  const res = await env.DB.batch([
    env.DB.prepare(`UPDATE accounts SET vault_seq = vault_seq + 1, updated_at = ?5 WHERE account_id = ?1 AND ${guard} AND ${vmkGuard} RETURNING vault_seq`).bind(
      accountId,
      m.itemId,
      m.base,
      m.vmkId,
      now,
    ),
    env.DB.prepare(
      `INSERT INTO items (account_id, item_id, revision, seq, vmk_id, dek_wrap, body, deleted, updated_at, updated_by)
       SELECT ?1, ?2, ?5, vault_seq, ?4, ?6, ?7, ?8, ?9, ?10 FROM accounts WHERE account_id = ?1 AND ${guard} AND ${vmkGuard}
       ON CONFLICT(account_id, item_id) DO UPDATE SET revision = excluded.revision, seq = excluded.seq, vmk_id = excluded.vmk_id,
         dek_wrap = excluded.dek_wrap, body = excluded.body, deleted = excluded.deleted, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
    ).bind(accountId, m.itemId, m.base, m.vmkId, m.revision, m.dekWrap, m.body, m.deleted ? 1 : 0, now, deviceId),
    env.DB.prepare(
      `INSERT INTO mutations (account_id, mutation_id, request_hash, result, created_at)
       SELECT ?1, ?2, ?3, json_object('seq', a.vault_seq), ?4 FROM accounts a WHERE a.account_id = ?1
         AND EXISTS (SELECT 1 FROM items i WHERE i.account_id = ?1 AND i.item_id = ?5 AND i.revision = ?6 AND i.seq = a.vault_seq)`,
    ).bind(accountId, m.mutationId, m.hash, now, m.itemId, m.revision),
  ]);
  const applied = res[0]?.results[0] as { vault_seq: number } | undefined;
  if (applied !== undefined) return { status: "applied", seq: applied.vault_seq };
  // Not applied: explain why.
  const a = await loadAccount(env, accountId);
  if (a === null) throw new ApiError(401, "unauthorized");
  if (!equal(a.vmkId, m.vmkId)) return { status: "keyset_changed", vmk_id: encode(a.vmkId), keyset_version: a.keysetVersion };
  const cur = await env.DB.prepare("SELECT * FROM items WHERE account_id = ? AND item_id = ?").bind(accountId, m.itemId).first<ItemRow>();
  if (cur === null) return { status: "invalid", code: "unknown_item" };
  return { status: "conflict", current: wireRecord(cur) };
}

export async function push(request: Request, env: Env, now: number): Promise<Response> {
  const s = await requireSession(request, env, ["full"], now);
  await rateLimit(env, `push:${encode(s.deviceId)}`, 60, MINUTE, now);
  const req = obj(await readJson(request, 4 * 1024 * 1024 + 4096));
  const raw = arr(req, "mutations", 100);
  const results: unknown[] = [];
  for (const x of raw) {
    const m = await parseMutation(x);
    results.push(m === null ? { status: "invalid", code: "malformed" } : await applyOne(env, s.accountId, s.deviceId, m, now));
  }
  return json({ results });
}
