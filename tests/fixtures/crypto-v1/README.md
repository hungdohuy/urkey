# crypto-v1 test vectors

**Test-only values.** Never use these keys, passwords or ids for real data.

Vectors for `docs/security/cryptographic-design.md` (spec §12), generated from fixed inputs by
`crates/crypto-core/tests/vectors.rs`.

| File | Covers |
|------|--------|
| `encoding.json` | Secret Key / Recovery Key text format, lenient input, invalid input |
| `kdf-unlock.json` | Argon2id `P`, unlock root `U`, `KEK_unlock`, account auth public key; rejected parameters |
| `kdf-recovery.json` | Recovery root `R`, `KEK_recovery`, recovery auth public key |
| `containers.json` | Every container kind (header, AAD, exact bytes), the local-wrap AAD, tampering cases |
| `item.json` | Padding lengths and a padded example |
| `signatures.json` | Exact bytes of every signed message and their Ed25519 signatures |

TOTP vectors (RFC 6238) belong to `vault-core` and arrive in roadmap P2.

## Check

```bash
# Rust (native): rebuild every vector and compare with these files
cargo test -p crypto-core --features test-vectors --test vectors

# Independent reproduction (Python, different libraries: argon2-cffi, cryptography, PyNaCl)
python3 -m venv .venv && .venv/bin/pip install -r tests/interop/python/requirements.txt
.venv/bin/python tests/interop/python/verify_crypto_v1.py
```

## Regenerate

```bash
URKEY_WRITE_VECTORS=1 cargo test -p crypto-core --features test-vectors --test vectors
```

A diff here means a wire format or derivation changed. That is a spec change and needs owner
approval (spec §15) before it is committed.

## About independence

`verify_crypto_v1.py` was written from the specification text with different libraries, and it
reproduces all values byte-for-byte. It was written by the same author (an AI coding agent) as
the Rust code, so it does not replace the independent human review required before real
credentials are stored (spec §13, roadmap M2).
