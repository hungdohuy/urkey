//! Test vectors for the crypto design v1 (spec §12).
//!
//! `cargo test -p crypto-core --features test-vectors --test vectors` rebuilds every vector from
//! fixed **test-only** inputs and checks it against `tests/fixtures/crypto-v1/*.json`.
//! Set `URKEY_WRITE_VECTORS=1` to (re)write the files instead; review the diff before committing,
//! because a change means the wire format or a derivation changed.
#![cfg(feature = "test-vectors")]
// Test-only file: panicking on malformed fixtures is the desired failure mode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use crypto_core::CryptoError;
use crypto_core::container::{self, Context, ItemContent};
use crypto_core::encoding;
use crypto_core::ids::{AccountId, DeviceId, ItemId, KdfSalt, SnapshotId, VmkId};
use crypto_core::kdf::{self, KdfParams};
use crypto_core::padding;
use crypto_core::secret::{
    AccountSecretKey, ItemKey, RecoveryKek, RecoveryKey, UnlockKek, VaultMasterKey,
};
use crypto_core::sign::{self, AuthKey};
use serde_json::{Value, json};

const NOTE: &str = "TEST-ONLY values for urkey crypto design v1. Never use these keys, passwords or ids for real data.";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic test-only byte pattern: start, start+1, ... (wrapping).
fn pattern<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

const ACCOUNT: AccountId = AccountId::from_bytes([0x11; 16]);
const ITEM: ItemId = ItemId::from_bytes([0x22; 16]);
const VMK_ID: VmkId = VmkId::from_bytes([0x33; 16]);
const DEVICE: DeviceId = DeviceId::from_bytes([0x44; 16]);
const SNAPSHOT: SnapshotId = SnapshotId::from_bytes([0x55; 16]);
const SALT: KdfSalt = KdfSalt::from_bytes([0x66; 16]);

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/crypto-v1")
}

fn encoding_vectors() -> Value {
    let asks: Vec<Value> = [pattern::<16>(0x00), [0xFF; 16], pattern::<16>(0xA0)]
        .iter()
        .map(|b| {
            let key = AccountSecretKey::from_slice(b).unwrap();
            json!({ "bytes": hex(b), "text": encoding::format_account_secret_key(&key).as_str() })
        })
        .collect();
    let rks: Vec<Value> = [pattern::<32>(0x00), [0xFF; 32], pattern::<32>(0x80)]
        .iter()
        .map(|b| {
            let key = RecoveryKey::from_slice(b).unwrap();
            json!({ "bytes": hex(b), "text": encoding::format_recovery_key(&key).as_str() })
        })
        .collect();
    let first_ask = encoding::format_account_secret_key(
        &AccountSecretKey::from_slice(&pattern::<16>(0)).unwrap(),
    )
    .to_string();
    let lenient = first_ask
        .to_ascii_lowercase()
        .replace('-', " ")
        .replace('0', "o")
        .replace('1', "l");
    let typo = {
        let mut c: Vec<char> = first_ask.chars().collect();
        c[6] = if c[6] == 'Z' { 'Y' } else { 'Z' };
        c.into_iter().collect::<String>()
    };
    json!({
        "_note": NOTE,
        "account_secret_keys": asks,
        "recovery_keys": rks,
        "valid_alternate_inputs": [
            { "type": "account_secret_key", "input": lenient, "bytes": hex(&pattern::<16>(0)) }
        ],
        "invalid_inputs": [
            { "type": "account_secret_key", "input": typo, "reason": "check symbol mismatch" },
            { "type": "account_secret_key", "input": &first_ask[..first_ask.len() - 1], "reason": "too short" },
            { "type": "account_secret_key", "input": format!("{first_ask}0"), "reason": "too long" },
            { "type": "account_secret_key", "input": first_ask.replacen("UK1", "UKR1", 1), "reason": "wrong prefix" },
            { "type": "account_secret_key", "input": "UK1-UUUUUU-UUUUU-UUUUU-UUUUU-UUUUU0", "reason": "U is check-only" },
            { "type": "account_secret_key", "input": "UK1-000000-00000-00000-00000-000010", "reason": "non-zero padding bits" }
        ]
    })
}

fn unlock_case(name: &str, password: &str, ask: [u8; 16], params: KdfParams) -> Value {
    let ask_key = AccountSecretKey::from_slice(&ask).unwrap();
    let (p, u) =
        kdf::unlock_intermediates_for_vectors(password, &ask_key, &ACCOUNT, &SALT, &params)
            .unwrap();
    let keys = kdf::derive_unlock(password, &ask_key, &ACCOUNT, &SALT, &params).unwrap();
    json!({
        "name": name,
        "password_utf8": hex(password.as_bytes()),
        "account_secret_key": hex(&ask),
        "account_id": hex(ACCOUNT.as_bytes()),
        "kdf_salt": hex(SALT.as_bytes()),
        "kdf_params": { "m_kib": params.m_kib(), "t": params.t(), "p": params.p(), "encoded": hex(&params.encode()) },
        "argon2id_output_P": hex(&p),
        "unlock_root_U": hex(&u),
        "kek_unlock": hex(keys.kek.expose_secret()),
        "auth_public_key": hex(&keys.auth.public_key()),
    })
}

fn kdf_unlock_vectors() -> Value {
    let low = KdfParams::new_unchecked_for_vectors(256, 1, 1);
    json!({
        "_note": NOTE,
        "_comment": "Cases with m_kib below 32768 use deliberately weak parameters that real clients reject (spec §4.2).",
        "cases": [
            unlock_case("ascii, low params", "urkey test vector password", pattern::<16>(0x01), low),
            unlock_case("nfkc: U+FB01 ligature equals 'fi', low params", "\u{FB01}", pattern::<16>(0x01), low),
            unlock_case("unicode, low params", "mật khẩu 🔑", pattern::<16>(0x70), KdfParams::new_unchecked_for_vectors(512, 2, 2)),
            unlock_case("ascii, default params", "urkey test vector password", pattern::<16>(0x01), KdfParams::DEFAULT),
        ],
        "rejected_kdf_params": [
            hex(&KdfParams::new_unchecked_for_vectors(32_767, 3, 1).encode()),
            hex(&KdfParams::new_unchecked_for_vectors(65_536, 1, 1).encode()),
            hex(&KdfParams::new_unchecked_for_vectors(1_048_577, 3, 1).encode()),
            hex(&KdfParams::new_unchecked_for_vectors(65_536, 21, 1).encode()),
            hex(&KdfParams::new_unchecked_for_vectors(65_536, 3, 0).encode()),
            "020001000000000003000000 01".replace(' ', ""),
        ]
    })
}

fn kdf_recovery_vectors() -> Value {
    let cases: Vec<Value> = [pattern::<32>(0x00), pattern::<32>(0x90)]
        .iter()
        .map(|rk| {
            let key = RecoveryKey::from_slice(rk).unwrap();
            let keys = kdf::derive_recovery(&key, &ACCOUNT).unwrap();
            json!({
                "recovery_key": hex(rk),
                "account_id": hex(ACCOUNT.as_bytes()),
                "recovery_root_R": hex(&kdf::recovery_root_for_vectors(&key, &ACCOUNT)),
                "kek_recovery": hex(keys.kek.expose_secret()),
                "recovery_auth_public_key": hex(&keys.auth.public_key()),
            })
        })
        .collect();
    json!({ "_note": NOTE, "cases": cases })
}

fn context_json(ctx: &Context) -> Value {
    match *ctx {
        Context::UnlockEnvelope {
            account_id,
            vmk_id,
            kdf_params,
            kdf_salt,
        } => json!({
            "account_id": hex(account_id.as_bytes()), "vmk_id": hex(vmk_id.as_bytes()),
            "kdf_params": hex(&kdf_params.encode()), "kdf_salt": hex(kdf_salt.as_bytes()) }),
        Context::RecoveryEnvelope { account_id, vmk_id } => json!({
            "account_id": hex(account_id.as_bytes()), "vmk_id": hex(vmk_id.as_bytes()) }),
        Context::DekWrap {
            account_id,
            item_id,
            vmk_id,
        } => json!({
            "account_id": hex(account_id.as_bytes()), "item_id": hex(item_id.as_bytes()), "vmk_id": hex(vmk_id.as_bytes()) }),
        Context::ItemPayload {
            account_id,
            item_id,
            revision,
        }
        | Context::Tombstone {
            account_id,
            item_id,
            revision,
        } => json!({
            "account_id": hex(account_id.as_bytes()), "item_id": hex(item_id.as_bytes()), "revision": revision }),
        Context::Snapshot {
            account_id,
            snapshot_id,
        } => json!({
            "account_id": hex(account_id.as_bytes()), "snapshot_id": hex(snapshot_id.as_bytes()) }),
        Context::LocalSecretKeyWrap {
            account_id,
            device_id,
        } => json!({
            "account_id": hex(account_id.as_bytes()), "device_id": hex(device_id.as_bytes()) }),
    }
}

fn kind_name(ctx: &Context) -> &'static str {
    match ctx {
        Context::UnlockEnvelope { .. } => "unlock_envelope",
        Context::RecoveryEnvelope { .. } => "recovery_envelope",
        Context::DekWrap { .. } => "dek_wrap",
        Context::ItemPayload { .. } => "item_payload",
        Context::Tombstone { .. } => "tombstone",
        Context::Snapshot { .. } => "snapshot",
        Context::LocalSecretKeyWrap { .. } => "local_secret_key_wrap",
    }
}

struct Sealed {
    ctx: Context,
    key: [u8; 32],
    nonce: [u8; 24],
    plaintext: Vec<u8>,
}

fn sealed_cases() -> Vec<Sealed> {
    let vmk = pattern::<32>(0xB0);
    let dek = pattern::<32>(0xC0);
    let body = br#"{"schema":1,"type":"note","title":"test vector"}"#;
    vec![
        Sealed {
            ctx: Context::UnlockEnvelope {
                account_id: ACCOUNT,
                vmk_id: VMK_ID,
                kdf_params: KdfParams::DEFAULT,
                kdf_salt: SALT,
            },
            key: pattern::<32>(0xA0),
            nonce: pattern::<24>(0x01),
            plaintext: vmk.to_vec(),
        },
        Sealed {
            ctx: Context::RecoveryEnvelope {
                account_id: ACCOUNT,
                vmk_id: VMK_ID,
            },
            key: pattern::<32>(0xD0),
            nonce: pattern::<24>(0x21),
            plaintext: vmk.to_vec(),
        },
        Sealed {
            ctx: Context::DekWrap {
                account_id: ACCOUNT,
                item_id: ITEM,
                vmk_id: VMK_ID,
            },
            key: vmk,
            nonce: pattern::<24>(0x41),
            plaintext: dek.to_vec(),
        },
        Sealed {
            ctx: Context::ItemPayload {
                account_id: ACCOUNT,
                item_id: ITEM,
                revision: 7,
            },
            key: dek,
            nonce: pattern::<24>(0x61),
            plaintext: padding::pad(body).unwrap().to_vec(),
        },
        Sealed {
            ctx: Context::Tombstone {
                account_id: ACCOUNT,
                item_id: ITEM,
                revision: 8,
            },
            key: dek,
            nonce: pattern::<24>(0x81),
            plaintext: Vec::new(),
        },
        Sealed {
            ctx: Context::Snapshot {
                account_id: ACCOUNT,
                snapshot_id: SNAPSHOT,
            },
            key: pattern::<32>(0xE0),
            nonce: pattern::<24>(0xA1),
            plaintext: b"snapshot test vector".to_vec(),
        },
    ]
}

fn container_vectors() -> Value {
    let cases: Vec<Value> = sealed_cases()
        .iter()
        .map(|c| {
            let sealed =
                container::seal_with_nonce(&c.key, &c.ctx, &c.nonce, &c.plaintext).unwrap();
            json!({
                "kind": kind_name(&c.ctx),
                "context": context_json(&c.ctx),
                "key": hex(&c.key),
                "nonce": hex(&c.nonce),
                "plaintext": hex(&c.plaintext),
                "aad": hex(&c.ctx.aad()),
                "container": hex(&sealed),
            })
        })
        .collect();
    let local = Context::LocalSecretKeyWrap {
        account_id: ACCOUNT,
        device_id: DEVICE,
    };
    json!({
        "_note": NOTE,
        "cases": cases,
        "aad_only": [{
            "kind": kind_name(&local),
            "context": context_json(&local),
            "aad": hex(&local.aad()),
            "_comment": "Sealed with AES-256-GCM by WebCrypto on the web client; crypto-core only defines the header and AAD."
        }],
        "negative": negative_cases(),
    })
}

/// Each entry must fail to open with the single Decrypt error.
fn negative_cases() -> Value {
    let item = &sealed_cases()[3];
    let good =
        container::seal_with_nonce(&item.key, &item.ctx, &item.nonce, &item.plaintext).unwrap();
    let flip = |i: usize| {
        let mut b = good.clone();
        b[i] ^= 0x01;
        hex(&b)
    };
    json!([
        { "description": "header kind byte changed", "container": flip(3), "revision": 7 },
        { "description": "key_ref byte changed", "container": flip(10), "revision": 7 },
        { "description": "nonce byte changed", "container": flip(25), "revision": 7 },
        { "description": "ciphertext byte changed", "container": flip(60), "revision": 7 },
        { "description": "tag byte changed", "container": flip(good.len() - 1), "revision": 7 },
        { "description": "truncated", "container": hex(&good[..good.len() - 1]), "revision": 7 },
        { "description": "valid container, wrong revision in AAD (rollback)", "container": hex(&good), "revision": 6 },
    ])
}

fn item_vectors() -> Value {
    let lens = [
        0usize,
        1,
        508,
        509,
        1020,
        1021,
        65_532,
        65_533,
        131_068,
        131_069,
        1 << 20,
    ];
    let table: Vec<Value> = lens
        .iter()
        .map(|&l| json!({ "body_len": l, "padded_len": padding::padded_len(l).unwrap() }))
        .collect();
    let body = br#"{"schema":1,"type":"note","title":"test vector"}"#;
    json!({
        "_note": NOTE,
        "padded_lengths": table,
        "max_body_len": padding::MAX_BODY_LEN,
        "padded_example": { "body": hex(body), "padded": hex(&padding::pad(body).unwrap()) },
    })
}

fn signature_vectors() -> Value {
    let key = AuthKey::device_key_from_seed(&pattern::<32>(0x07));
    let pk = key.public_key();
    let nonce = pattern::<32>(0x30);
    let body_hash = sign::sha256(b"{\"test\":\"vector\"}");
    let origin = "https://api.urkey.test";
    let cases = [
        ("create", sign::create_message(&ACCOUNT, &body_hash)),
        (
            "login",
            sign::login_message(&ACCOUNT, &nonce, &DEVICE, &pk, origin),
        ),
        (
            "recovery",
            sign::recovery_message(&ACCOUNT, &nonce, &pk, origin),
        ),
        (
            "stepup",
            sign::stepup_message(&ACCOUNT, &nonce, "rotate_recovery_key", &body_hash),
        ),
        ("refresh", sign::refresh_message(&ACCOUNT, &nonce, &DEVICE)),
    ];
    let out: Vec<Value> = cases
        .iter()
        .map(|(name, msg)| json!({ "name": name, "message": hex(msg), "signature": hex(&key.sign(msg)) }))
        .collect();
    json!({
        "_note": NOTE,
        "signing_seed": hex(&pattern::<32>(0x07)),
        "public_key": hex(&pk),
        "inputs": {
            "account_id": hex(ACCOUNT.as_bytes()), "device_id": hex(DEVICE.as_bytes()), "nonce": hex(&nonce),
            "api_origin": origin, "operation": "rotate_recovery_key",
            "request_body": "{\"test\":\"vector\"}", "request_body_sha256": hex(&body_hash)
        },
        "cases": out,
    })
}

fn all_sets() -> Vec<(&'static str, Value)> {
    vec![
        ("encoding.json", encoding_vectors()),
        ("kdf-unlock.json", kdf_unlock_vectors()),
        ("kdf-recovery.json", kdf_recovery_vectors()),
        ("containers.json", container_vectors()),
        ("item.json", item_vectors()),
        ("signatures.json", signature_vectors()),
    ]
}

#[test]
fn vectors_match_committed_fixtures() {
    let dir = fixtures_dir();
    let write = std::env::var("URKEY_WRITE_VECTORS").is_ok_and(|v| v == "1");
    for (name, value) in all_sets() {
        let path = dir.join(name);
        if write {
            let mut text = serde_json::to_string_pretty(&value).unwrap();
            text.push('\n');
            std::fs::write(&path, text).unwrap();
        } else {
            let committed: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(
                committed, value,
                "{name} differs from the generated vectors"
            );
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn encoded_inputs_parse_as_documented() {
    let v = encoding_vectors();
    for case in v["account_secret_keys"].as_array().unwrap() {
        let key = encoding::parse_account_secret_key(case["text"].as_str().unwrap()).unwrap();
        assert_eq!(hex(key.expose_secret()), case["bytes"]);
    }
    for case in v["recovery_keys"].as_array().unwrap() {
        let key = encoding::parse_recovery_key(case["text"].as_str().unwrap()).unwrap();
        assert_eq!(hex(key.expose_secret()), case["bytes"]);
    }
    for case in v["valid_alternate_inputs"].as_array().unwrap() {
        let key = encoding::parse_account_secret_key(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(hex(key.expose_secret()), case["bytes"]);
    }
    for case in v["invalid_inputs"].as_array().unwrap() {
        assert!(
            encoding::parse_account_secret_key(case["input"].as_str().unwrap()).is_err(),
            "{}",
            case["reason"]
        );
    }
}

#[test]
fn rejected_params_are_rejected() {
    for enc in kdf_unlock_vectors()["rejected_kdf_params"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            KdfParams::decode(&unhex(enc.as_str().unwrap())),
            Err(CryptoError::KdfParamsRejected)
        );
    }
}

#[test]
fn sealed_containers_open_with_the_typed_api() {
    let a = AccountId::from_bytes([0x11; 16]);
    let cases = sealed_cases();
    let seal =
        |c: &Sealed| container::seal_with_nonce(&c.key, &c.ctx, &c.nonce, &c.plaintext).unwrap();

    let unlock = UnlockKek::from_slice(&cases[0].key).unwrap();
    let vmk = container::unwrap_vmk_unlock(
        &unlock,
        &seal(&cases[0]),
        a,
        VMK_ID,
        KdfParams::DEFAULT,
        SALT,
    )
    .unwrap();
    assert_eq!(vmk.expose_secret()[..], cases[0].plaintext[..]);

    let recovery = RecoveryKek::from_slice(&cases[1].key).unwrap();
    let vmk2 = container::unwrap_vmk_recovery(&recovery, &seal(&cases[1]), a, VMK_ID).unwrap();
    assert_eq!(vmk2.expose_secret(), vmk.expose_secret());

    let vmk_key = VaultMasterKey::from_slice(&cases[2].key).unwrap();
    let dek = container::unwrap_item_key(&vmk_key, VMK_ID, &seal(&cases[2]), a, ITEM).unwrap();
    assert_eq!(dek.expose_secret()[..], cases[2].plaintext[..]);

    let item_key = ItemKey::from_slice(&cases[3].key).unwrap();
    match container::open_item(&item_key, a, ITEM, 7, &seal(&cases[3])).unwrap() {
        ItemContent::Body(b) => assert_eq!(
            b.as_slice(),
            br#"{"schema":1,"type":"note","title":"test vector"}"#
        ),
        ItemContent::Deleted => panic!("expected body"),
    }
    assert!(matches!(
        container::open_item(&item_key, a, ITEM, 8, &seal(&cases[4])).unwrap(),
        ItemContent::Deleted
    ));

    for neg in negative_cases().as_array().unwrap() {
        let bytes = unhex(neg["container"].as_str().unwrap());
        let rev = neg["revision"].as_u64().unwrap();
        assert_eq!(
            container::open_item(&item_key, a, ITEM, rev, &bytes).unwrap_err(),
            CryptoError::Decrypt,
            "{}",
            neg["description"]
        );
    }
}

#[test]
fn signatures_verify() {
    let v = signature_vectors();
    let pk: [u8; 32] = unhex(v["public_key"].as_str().unwrap()).try_into().unwrap();
    for case in v["cases"].as_array().unwrap() {
        let msg = unhex(case["message"].as_str().unwrap());
        let sig: [u8; 64] = unhex(case["signature"].as_str().unwrap())
            .try_into()
            .unwrap();
        sign::verify(&pk, &msg, &sig).unwrap();
    }
}
