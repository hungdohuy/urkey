//! Runs the crypto-v1 vectors inside WebAssembly (Node) and measures Argon2id there.
//!
//! `wasm-pack test --node crates/crypto-core --features test-vectors`
//!
//! The fixtures are embedded at compile time because WASM tests have no file system.
#![cfg(all(target_arch = "wasm32", feature = "test-vectors"))]
// Test-only file: panicking on malformed fixtures is the desired failure mode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crypto_core::container::{self, Context};
use crypto_core::encoding;
use crypto_core::ids::{AccountId, ItemId, KdfSalt, SnapshotId, VmkId};
use crypto_core::kdf::{self, KdfParams};
use crypto_core::secret::{AccountSecretKey, RecoveryKey};
use crypto_core::sign::{self, AuthKey};
use serde_json::Value;
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    unhex(v.as_str().unwrap()).try_into().unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

#[wasm_bindgen_test]
fn encoding_vectors() {
    let v = fixture(include_str!(
        "../../../tests/fixtures/crypto-v1/encoding.json"
    ));
    for c in v["account_secret_keys"].as_array().unwrap() {
        let key = AccountSecretKey::from_slice(&unhex(c["bytes"].as_str().unwrap())).unwrap();
        assert_eq!(
            encoding::format_account_secret_key(&key).as_str(),
            c["text"].as_str().unwrap()
        );
    }
    for c in v["recovery_keys"].as_array().unwrap() {
        let key = RecoveryKey::from_slice(&unhex(c["bytes"].as_str().unwrap())).unwrap();
        assert_eq!(
            encoding::format_recovery_key(&key).as_str(),
            c["text"].as_str().unwrap()
        );
    }
}

#[wasm_bindgen_test]
fn kdf_vectors_and_argon2id_benchmark() {
    let v = fixture(include_str!(
        "../../../tests/fixtures/crypto-v1/kdf-unlock.json"
    ));
    for c in v["cases"].as_array().unwrap() {
        let p = &c["kdf_params"];
        let params = KdfParams::new_unchecked_for_vectors(
            p["m_kib"].as_u64().unwrap() as u32,
            p["t"].as_u64().unwrap() as u32,
            p["p"].as_u64().unwrap() as u32,
        );
        let password = String::from_utf8(unhex(c["password_utf8"].as_str().unwrap())).unwrap();
        let ask = AccountSecretKey::from_slice(&unhex(c["account_secret_key"].as_str().unwrap()))
            .unwrap();
        let start = now_ms();
        let keys = kdf::derive_unlock(
            &password,
            &ask,
            &AccountId::from_bytes(arr(&c["account_id"])),
            &KdfSalt::from_bytes(arr(&c["kdf_salt"])),
            &params,
        )
        .unwrap();
        let elapsed = now_ms() - start;
        assert_eq!(
            hex(keys.kek.expose_secret()),
            c["kek_unlock"].as_str().unwrap()
        );
        assert_eq!(
            hex(&keys.auth.public_key()),
            c["auth_public_key"].as_str().unwrap()
        );
        if params == KdfParams::DEFAULT {
            console_log!("BENCH argon2id m=64MiB t=3 p=1 (wasm32, Node): {elapsed:.0} ms");
        }
    }

    let r = fixture(include_str!(
        "../../../tests/fixtures/crypto-v1/kdf-recovery.json"
    ));
    for c in r["cases"].as_array().unwrap() {
        let rk = RecoveryKey::from_slice(&unhex(c["recovery_key"].as_str().unwrap())).unwrap();
        let keys =
            kdf::derive_recovery(&rk, &AccountId::from_bytes(arr(&c["account_id"]))).unwrap();
        assert_eq!(
            hex(keys.kek.expose_secret()),
            c["kek_recovery"].as_str().unwrap()
        );
        assert_eq!(
            hex(&keys.auth.public_key()),
            c["recovery_auth_public_key"].as_str().unwrap()
        );
    }
}

#[wasm_bindgen_test]
fn container_vectors() {
    let v = fixture(include_str!(
        "../../../tests/fixtures/crypto-v1/containers.json"
    ));
    for c in v["cases"].as_array().unwrap() {
        let x = &c["context"];
        let account_id = AccountId::from_bytes(arr(&x["account_id"]));
        let ctx = match c["kind"].as_str().unwrap() {
            "unlock_envelope" => Context::UnlockEnvelope {
                account_id,
                vmk_id: VmkId::from_bytes(arr(&x["vmk_id"])),
                kdf_params: KdfParams::decode(&unhex(x["kdf_params"].as_str().unwrap())).unwrap(),
                kdf_salt: KdfSalt::from_bytes(arr(&x["kdf_salt"])),
            },
            "recovery_envelope" => Context::RecoveryEnvelope {
                account_id,
                vmk_id: VmkId::from_bytes(arr(&x["vmk_id"])),
            },
            "dek_wrap" => Context::DekWrap {
                account_id,
                item_id: ItemId::from_bytes(arr(&x["item_id"])),
                vmk_id: VmkId::from_bytes(arr(&x["vmk_id"])),
            },
            "item_payload" => Context::ItemPayload {
                account_id,
                item_id: ItemId::from_bytes(arr(&x["item_id"])),
                revision: x["revision"].as_u64().unwrap(),
            },
            "tombstone" => Context::Tombstone {
                account_id,
                item_id: ItemId::from_bytes(arr(&x["item_id"])),
                revision: x["revision"].as_u64().unwrap(),
            },
            "snapshot" => Context::Snapshot {
                account_id,
                snapshot_id: SnapshotId::from_bytes(arr(&x["snapshot_id"])),
            },
            other => panic!("unexpected kind {other}"),
        };
        assert_eq!(hex(&ctx.aad()), c["aad"].as_str().unwrap());
        let sealed = container::seal_with_nonce(
            &arr(&c["key"]),
            &ctx,
            &arr(&c["nonce"]),
            &unhex(c["plaintext"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            hex(&sealed),
            c["container"].as_str().unwrap(),
            "{}",
            c["kind"]
        );
    }
}

#[wasm_bindgen_test]
fn signature_vectors() {
    let v = fixture(include_str!(
        "../../../tests/fixtures/crypto-v1/signatures.json"
    ));
    let key = AuthKey::device_key_from_seed(&arr(&v["signing_seed"]));
    assert_eq!(hex(&key.public_key()), v["public_key"].as_str().unwrap());
    for c in v["cases"].as_array().unwrap() {
        let msg = unhex(c["message"].as_str().unwrap());
        assert_eq!(hex(&key.sign(&msg)), c["signature"].as_str().unwrap());
        sign::verify(&key.public_key(), &msg, &arr(&c["signature"])).unwrap();
    }
}

#[wasm_bindgen_test]
fn csprng_works_in_wasm() {
    let a = crypto_core::secret::ItemKey::generate().unwrap();
    let b = crypto_core::secret::ItemKey::generate().unwrap();
    assert_ne!(a.expose_secret(), b.expose_secret());
}
