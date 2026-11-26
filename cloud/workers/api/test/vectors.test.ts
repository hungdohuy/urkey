import { describe, expect, it } from "vitest";
import sig from "../../../../tests/fixtures/crypto-v1/signatures.json";
import { decode, encode } from "../src/b64";
import { messages, sha256, verifyEd25519 } from "../src/crypto";

const h = (s: string) => decode(Buffer.from(s, "hex").toString("base64url")) ?? new Uint8Array();

describe("crypto-v1 signature vectors (shared with Rust)", () => {
  const i = sig.inputs;
  const acct = h(i.account_id);
  const dev = h(i.device_id);
  const nonce = h(i.nonce);
  const pk = h(sig.public_key);

  it("builds byte-identical messages", async () => {
    const bodyHash = await sha256(new TextEncoder().encode(i.request_body));
    expect(encode(bodyHash)).toBe(encode(h(i.request_body_sha256)));
    const built: Record<string, Uint8Array> = {
      create: messages.create(acct, bodyHash),
      login: messages.login(acct, nonce, dev, pk, i.api_origin),
      recovery: messages.recovery(acct, nonce, pk, i.api_origin),
      stepup: messages.stepup(acct, nonce, i.operation, bodyHash),
      refresh: messages.refresh(acct, nonce, dev),
    };
    for (const c of sig.cases) {
      expect(encode(built[c.name] ?? new Uint8Array()), c.name).toBe(encode(h(c.message)));
    }
  });

  it("verifies every signature and rejects tampering", async () => {
    for (const c of sig.cases) {
      const msg = h(c.message);
      expect(await verifyEd25519(pk, msg, h(c.signature)), c.name).toBe(true);
      const bad = msg.slice();
      bad[0] = (bad[0] ?? 0) ^ 1;
      expect(await verifyEd25519(pk, bad, h(c.signature))).toBe(false);
    }
  });
});
