#!/usr/bin/env python3
"""Independent check of tests/fixtures/crypto-v1 against docs/security/cryptographic-design.md.

Written from the specification, not from the Rust code, using different libraries:
argon2-cffi (Argon2id), cryptography (HKDF, Ed25519, SHA-256) and PyNaCl/libsodium
(XChaCha20-Poly1305). Every value in the fixtures is recomputed byte-for-byte.

Usage: python3 verify_crypto_v1.py [path/to/tests/fixtures/crypto-v1]
Exit code 0 means every vector was reproduced.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

FAILURES: list[str] = []
CHECKS = 0


def check(cond: bool, what: str) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(what)


def h(s: str) -> bytes:
    return bytes.fromhex(s)


def lp(b: bytes) -> bytes:
    """LP(x) = u32be(len(x)) || x  (spec §1)."""
    return struct.pack(">I", len(b)) + b


# ---------------------------------------------------------------- §3.2 encodings
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CHECK_EXTRA = "*~$=U"


def b32(data: bytes) -> str:
    bits = "".join(f"{x:08b}" for x in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(CROCKFORD[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def check_symbol(data: bytes) -> str:
    return (CROCKFORD + CHECK_EXTRA)[int.from_bytes(data, "big") % 37]


def format_key(prefix: str, groups: list[int], data: bytes) -> str:
    payload = b32(data)
    parts, pos = [], 0
    for n in groups:
        parts.append(payload[pos:pos + n])
        pos += n
    parts[-1] += check_symbol(data)
    return "-".join([prefix] + parts)


def parse_key(prefix: str, nbytes: int, text: str) -> bytes | None:
    s = "".join(c for c in text if c != "-" and not c.isspace()).upper()
    s = s.replace("I", "1").replace("L", "1").replace("O", "0")
    if not s.startswith(prefix):
        return None
    s = s[len(prefix):]
    nsym = -(-nbytes * 8 // 5)
    if len(s) != nsym + 1:
        return None
    payload, chk = s[:nsym], s[nsym:]
    if any(c not in CROCKFORD for c in payload):
        return None
    bits = "".join(f"{CROCKFORD.index(c):05b}" for c in payload)
    data_bits, pad_bits = bits[:nbytes * 8], bits[nbytes * 8:]
    if "1" in pad_bits:
        return None
    data = int(data_bits, 2).to_bytes(nbytes, "big")
    return data if check_symbol(data) == chk else None


def verify_encoding(v: dict) -> None:
    for c in v["account_secret_keys"]:
        check(format_key("UK1", [6, 5, 5, 5, 5], h(c["bytes"])) == c["text"], f"ASK format {c['text']}")
        check(parse_key("UK1", 16, c["text"]) == h(c["bytes"]), f"ASK parse {c['text']}")
    for c in v["recovery_keys"]:
        check(format_key("UKR1", [4] * 13, h(c["bytes"])) == c["text"], f"RK format {c['text']}")
        check(parse_key("UKR1", 32, c["text"]) == h(c["bytes"]), f"RK parse {c['text']}")
    for c in v["valid_alternate_inputs"]:
        check(parse_key("UK1", 16, c["input"]) == h(c["bytes"]), f"lenient parse {c['input']}")
    for c in v["invalid_inputs"]:
        check(parse_key("UK1", 16, c["input"]) is None, f"invalid accepted: {c['reason']}")


# ---------------------------------------------------------------- §4 KDFs
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()  # RFC 5869 §2.2


def hkdf_expand(prk: bytes, info: bytes, n: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=n, info=info).derive(prk)


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def decode_params(enc: bytes) -> tuple[int, int, int] | None:
    """Spec §4.2: alg 0x01, floor m>=32768 t>=2 p>=1, ceiling m<=1 GiB t<=20."""
    if len(enc) != 13 or enc[0] != 0x01:
        return None
    m, t, p = struct.unpack(">III", enc[1:])
    if not (32768 <= m <= 1048576 and 2 <= t <= 20 and p >= 1):
        return None
    return m, t, p


def verify_unlock(v: dict) -> None:
    for c in v["cases"]:
        name = c["name"]
        pw = unicodedata.normalize("NFKC", h(c["password_utf8"]).decode("utf-8")).encode("utf-8")
        prm = c["kdf_params"]
        check(h(prm["encoded"]) == b"\x01" + struct.pack(">III", prm["m_kib"], prm["t"], prm["p"]), f"{name}: params encoding")
        p = hash_secret_raw(pw, h(c["kdf_salt"]), time_cost=prm["t"], memory_cost=prm["m_kib"],
                            parallelism=prm["p"], hash_len=32, type=Type.ID, version=19)
        check(p == h(c["argon2id_output_P"]), f"{name}: Argon2id P")
        salt = lp(b"urkey/v1/unlock-root") + h(c["account_id"])
        u = hkdf_extract(salt, p + h(c["account_secret_key"]))
        check(u == h(c["unlock_root_U"]), f"{name}: unlock root U")
        check(hkdf_expand(u, b"urkey/v1/kek/unlock") == h(c["kek_unlock"]), f"{name}: KEK_unlock")
        seed = hkdf_expand(u, b"urkey/v1/auth/account-ed25519")
        check(ed25519_public(seed) == h(c["auth_public_key"]), f"{name}: auth public key")
    for enc in v["rejected_kdf_params"]:
        check(decode_params(h(enc)) is None, f"params should be rejected: {enc}")
    check(decode_params(h("01000100000000000300000001")) == (65536, 3, 1), "default params accepted")


def verify_recovery(v: dict) -> None:
    for c in v["cases"]:
        r = hkdf_extract(lp(b"urkey/v1/recovery-root") + h(c["account_id"]), h(c["recovery_key"]))
        check(r == h(c["recovery_root_R"]), "recovery root R")
        check(hkdf_expand(r, b"urkey/v1/kek/recovery") == h(c["kek_recovery"]), "KEK_recovery")
        seed = hkdf_expand(r, b"urkey/v1/auth/recovery-ed25519")
        check(ed25519_public(seed) == h(c["recovery_auth_public_key"]), "recovery auth public key")


# ---------------------------------------------------------------- §5-6 containers
KINDS = {"unlock_envelope": 1, "recovery_envelope": 2, "dek_wrap": 3, "item_payload": 4,
         "tombstone": 5, "local_secret_key_wrap": 6, "snapshot": 7}


def key_ref_and_context(kind: str, ctx: dict) -> tuple[bytes, bytes]:
    a = h(ctx["account_id"])
    if kind == "unlock_envelope":
        return h(ctx["vmk_id"]), a + h(ctx["kdf_params"]) + h(ctx["kdf_salt"])
    if kind == "recovery_envelope":
        return h(ctx["vmk_id"]), a
    if kind == "dek_wrap":
        return h(ctx["vmk_id"]), a + h(ctx["item_id"])
    if kind in ("item_payload", "tombstone"):
        return h(ctx["item_id"]), a + h(ctx["item_id"]) + struct.pack(">Q", ctx["revision"])
    if kind == "snapshot":
        return h(ctx["snapshot_id"]), a + lp(h(ctx["snapshot_id"]))
    if kind == "local_secret_key_wrap":
        return h(ctx["device_id"]), a + lp(h(ctx["device_id"]))
    raise ValueError(kind)


def aad_for(kind: str, ctx: dict) -> bytes:
    key_ref, context = key_ref_and_context(kind, ctx)
    alg = 2 if kind == "local_secret_key_wrap" else 1
    return b"UK" + bytes([1, KINDS[kind], alg]) + key_ref + context


def open_container(key: bytes, kind: str, ctx: dict, data: bytes) -> bytes | None:
    """Spec §6.2 parsing rules; returns None on any failure."""
    if len(data) < 21 + 24 + 16 or data[:3] != b"UK\x01" or data[3] != KINDS[kind] or data[4] != 1:
        return None
    key_ref, _ = key_ref_and_context(kind, ctx)
    if data[5:21] != key_ref:
        return None
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(data[45:], aad_for(kind, ctx), data[21:45], key)
    except Exception:  # noqa: BLE001 - any failure is the single decrypt error
        return None


def verify_containers(v: dict) -> None:
    item_case = None
    for c in v["cases"]:
        kind, ctx = c["kind"], c["context"]
        aad = aad_for(kind, ctx)
        check(aad == h(c["aad"]), f"{kind}: AAD")
        ct = crypto_aead_xchacha20poly1305_ietf_encrypt(h(c["plaintext"]), aad, h(c["nonce"]), h(c["key"]))
        check(aad[:21] + h(c["nonce"]) + ct == h(c["container"]), f"{kind}: container bytes")
        check(open_container(h(c["key"]), kind, ctx, h(c["container"])) == h(c["plaintext"]), f"{kind}: open")
        if kind == "item_payload":
            item_case = c
    for c in v["aad_only"]:
        check(aad_for(c["kind"], c["context"]) == h(c["aad"]), f"{c['kind']}: AAD")
    assert item_case is not None
    for n in v["negative"]:
        ctx = dict(item_case["context"], revision=n["revision"])
        check(open_container(h(item_case["key"]), "item_payload", ctx, h(n["container"])) is None,
              f"negative case opened: {n['description']}")


# ---------------------------------------------------------------- §5.4 padding
def padded_len(n: int) -> int:
    total = n + 4
    if total <= 512:
        return 512
    if total <= 65536:
        return 1 << (total - 1).bit_length()
    return -(-total // 65536) * 65536


def verify_item(v: dict) -> None:
    for row in v["padded_lengths"]:
        check(padded_len(row["body_len"]) == row["padded_len"], f"padded_len({row['body_len']})")
    body = h(v["padded_example"]["body"])
    padded = struct.pack(">I", len(body)) + body
    padded += b"\0" * (padded_len(len(body)) - len(padded))
    check(padded == h(v["padded_example"]["padded"]), "padded example")


# ---------------------------------------------------------------- §7 signatures
def verify_signatures(v: dict) -> None:
    i = v["inputs"]
    acct, dev, nonce, origin = h(i["account_id"]), h(i["device_id"]), h(i["nonce"]), i["api_origin"].encode()
    body_hash = hashlib.sha256(i["request_body"].encode()).digest()
    check(body_hash == h(i["request_body_sha256"]), "request body hash")
    seed = h(v["signing_seed"])
    pk = ed25519_public(seed)
    check(pk == h(v["public_key"]), "signing public key")
    expected = {
        "create": lp(b"urkey/v1/sig/create") + acct + body_hash,
        "login": lp(b"urkey/v1/sig/login") + acct + nonce + dev + pk + lp(origin),
        "recovery": lp(b"urkey/v1/sig/recovery") + acct + nonce + pk + lp(origin),
        "stepup": lp(b"urkey/v1/sig/stepup") + acct + nonce + lp(i["operation"].encode()) + body_hash,
        "refresh": lp(b"urkey/v1/sig/refresh") + acct + nonce + dev,
    }
    key = Ed25519PrivateKey.from_private_bytes(seed)
    for c in v["cases"]:
        msg = expected[c["name"]]
        check(msg == h(c["message"]), f"{c['name']}: message bytes")
        check(key.sign(msg) == h(c["signature"]), f"{c['name']}: signature bytes")
        Ed25519PublicKey.from_public_bytes(pk).verify(h(c["signature"]), msg)


def main() -> int:
    default = Path(__file__).resolve().parents[2] / "fixtures" / "crypto-v1"
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    load = lambda name: json.loads((root / name).read_text(encoding="utf-8"))  # noqa: E731
    verify_encoding(load("encoding.json"))
    verify_unlock(load("kdf-unlock.json"))
    verify_recovery(load("kdf-recovery.json"))
    verify_containers(load("containers.json"))
    verify_item(load("item.json"))
    verify_signatures(load("signatures.json"))
    if FAILURES:
        print(f"FAILED {len(FAILURES)} of {CHECKS} checks:")
        for f in FAILURES:
            print("  -", f)
        return 1
    print(f"OK: reproduced all {CHECKS} checks independently")
    return 0


if __name__ == "__main__":
    sys.exit(main())
