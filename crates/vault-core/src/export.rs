//! Encrypted export files (roadmap P7, ADR 0017).
//!
//! An export is the account's own ciphertext, copied as-is. It holds the unlock envelope with
//! its KDF salt and parameters, plus every live item record (DEK wrap + body) under the current
//! vault key. No new cryptographic construction is involved. Opening an export runs the normal
//! unlock (crypto §7.3) with the master password and Secret Key that were current when it was
//! made, then opens each record with [`record::open`] (§7.2). The AAD binds each record to its
//! account, item, revision and VMK generation.
//!
//! Restoring decrypts the items and re-encrypts them as **new** items in the target vault,
//! through the normal write path. Restoring into the same account adds copies.
//!
//! Limits (documented in ADR 0017): an export cannot be opened with the Recovery Key, and an
//! attacker holding the file can drop whole records without detection (they could also delete
//! the file). Anything else, such as changed, swapped or replayed records, fails authentication.

use std::collections::BTreeSet;

use crypto_core::CryptoError;
use crypto_core::ids::{AccountId, ItemId, KdfSalt, VmkId};
use crypto_core::kdf::KdfParams;
use crypto_core::secret::AccountSecretKey;
use serde::{Deserialize, Serialize};

use crate::account::{self, UnlockMaterial};
use crate::b64::B64;
use crate::item::Item;
use crate::record::{self, ItemRecord};
use crate::{Result, VaultError};

/// `format` value of every export file.
pub const FORMAT: &str = "urkey-export";
/// The only version this client writes and reads.
pub const VERSION: u32 = 1;
/// Upper bound on records (the server's per-account limit).
pub const MAX_ITEMS: usize = 10_000;

/// The export file (JSON). Binary fields are base64url without padding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFile {
    /// Always [`FORMAT`].
    pub format: String,
    /// Always [`VERSION`].
    pub version: u32,
    /// When the export was made (Unix ms). Informational, not authenticated.
    pub created_at: i64,
    /// Account the records belong to.
    pub account_id: B64,
    /// Argon2id salt of the unlock envelope.
    pub kdf_salt: B64,
    /// Encoded Argon2id parameters of the unlock envelope.
    pub kdf_params: B64,
    /// VMK generation of the envelope and of every record.
    pub vmk_id: B64,
    /// Unlock envelope (container 0x01).
    pub unlock_env: B64,
    /// Live item records.
    pub items: Vec<ExportRecord>,
}

/// One item record as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRecord {
    /// Item id.
    pub item_id: B64,
    /// Revision bound into the AAD.
    pub revision: u64,
    /// Container 0x03.
    pub dek_wrap: B64,
    /// Container 0x04.
    pub body: B64,
}

/// Builds an export from the unlock material and the device's current records. Tombstones and
/// records under another VMK generation are left out.
pub fn build(material: &UnlockMaterial, records: &[ItemRecord], now_ms: i64) -> Result<ExportFile> {
    let items: Vec<ExportRecord> = records
        .iter()
        .filter(|r| r.vmk_id == material.vmk_id && !r.claims_deleted())
        .map(|r| ExportRecord {
            item_id: B64(r.item_id.as_bytes().to_vec()),
            revision: r.revision,
            dek_wrap: B64(r.dek_wrap.clone()),
            body: B64(r.body.clone()),
        })
        .collect();
    if items.len() > MAX_ITEMS {
        return Err(VaultError::Invalid("too many items to export"));
    }
    Ok(ExportFile {
        format: FORMAT.to_owned(),
        version: VERSION,
        created_at: now_ms,
        account_id: B64(material.account_id.as_bytes().to_vec()),
        kdf_salt: B64(material.kdf_salt.as_bytes().to_vec()),
        kdf_params: B64(material.kdf_params.encode().to_vec()),
        vmk_id: B64(material.vmk_id.as_bytes().to_vec()),
        unlock_env: B64(material.unlock_env.clone()),
        items,
    })
}

/// Parses an export file. Unknown formats and versions are rejected with a non-secret error.
pub fn parse(json: &[u8]) -> Result<ExportFile> {
    // Check format and version first, so a newer file gets a clear error and not a schema error.
    #[derive(Deserialize)]
    struct Header {
        format: String,
        version: u32,
    }
    let header: Header = serde_json::from_slice(json)
        .map_err(|_| VaultError::Invalid("not an urkey export file"))?;
    if header.format != FORMAT {
        return Err(VaultError::Invalid("not an urkey export file"));
    }
    if header.version != VERSION {
        return Err(VaultError::Invalid(
            "this export needs a newer version of urkey",
        ));
    }
    let file: ExportFile =
        serde_json::from_slice(json).map_err(|_| VaultError::Invalid("export file is damaged"))?;
    if file.items.len() > MAX_ITEMS {
        return Err(VaultError::Invalid("export file is damaged"));
    }
    Ok(file)
}

/// Opens an export with the master password and Secret Key current when it was made. Returns
/// the decrypted items. Any authentication failure (wrong password, wrong Secret Key, or a
/// changed envelope or record) is the same [`CryptoError::Decrypt`].
pub fn open(file: &ExportFile, password: &str, secret_key: &AccountSecretKey) -> Result<Vec<Item>> {
    let material = UnlockMaterial {
        account_id: AccountId::from_slice(&file.account_id.0)?,
        kdf_salt: KdfSalt::from_slice(&file.kdf_salt.0)?,
        kdf_params: KdfParams::decode(&file.kdf_params.0)?,
        unlock_env: file.unlock_env.0.clone(),
        vmk_id: VmkId::from_slice(&file.vmk_id.0)?,
    };
    let unlocked = account::unlock(&material, password, secret_key)?;
    let mut seen = BTreeSet::new();
    let mut items = Vec::with_capacity(file.items.len());
    for r in &file.items {
        let item_id = ItemId::from_slice(&r.item_id.0)?;
        if !seen.insert(*item_id.as_bytes()) {
            return Err(CryptoError::Decrypt.into());
        }
        let rec = ItemRecord {
            item_id,
            revision: r.revision,
            vmk_id: material.vmk_id,
            dek_wrap: r.dek_wrap.0.clone(),
            body: r.body.0.clone(),
        };
        // A tombstone in an export means the file was altered: build() never writes one.
        match record::open(&unlocked.vault, &rec)
            .map_err(|_| VaultError::from(CryptoError::Decrypt))?
            .item
        {
            Some(item) => items.push(item),
            None => return Err(CryptoError::Decrypt.into()),
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Content, NoteFields};
    use crate::record::VaultKey;
    use crate::wire::DeviceInfo;
    use crypto_core::ids::DeviceId;
    use crypto_core::sign::AuthKey;

    const PASSWORD: &str = "test-only export password";

    fn new_account() -> (account::NewAccount, UnlockMaterial) {
        let key = AuthKey::generate_device_key().unwrap();
        let device = DeviceInfo {
            device_id: B64(DeviceId::generate().unwrap().as_bytes().to_vec()),
            device_pk: B64(key.public_key().to_vec()),
            name: "Test".into(),
            platform: "cli".into(),
            client_version: "0.0.0".into(),
        };
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1).unwrap();
        let a = account::create_account("t@example.test", PASSWORD, &device, params).unwrap();
        let m = UnlockMaterial {
            account_id: a.vault.account_id,
            kdf_salt: KdfSalt::from_slice(&a.payload.kdf_salt.0).unwrap(),
            kdf_params: KdfParams::decode(&a.payload.kdf_params.0).unwrap(),
            unlock_env: a.payload.unlock_env.0.clone(),
            vmk_id: a.vault.vmk_id,
        };
        (a, m)
    }

    fn note(key: &VaultKey, text: &str) -> ItemRecord {
        let mut i = Item::new(Content::Note(NoteFields::default()), text, "t", "d");
        i.notes = text.into();
        record::seal_new(key, &i).unwrap().0
    }

    fn sample() -> (account::NewAccount, ExportFile) {
        let (a, m) = new_account();
        let live = note(&a.vault, "kept");
        let gone = note(&a.vault, "deleted");
        let gone_key = record::open(&a.vault, &gone).unwrap().item_key;
        let tomb = record::seal_delete(&a.vault, gone.item_id, &gone_key, gone.revision).unwrap();
        let file = build(&m, &[live, tomb], 1).unwrap();
        (a, file)
    }

    #[test]
    fn round_trip_through_json() {
        let (a, file) = sample();
        assert_eq!(file.items.len(), 1, "tombstones are not exported");
        let json = serde_json::to_vec(&file).unwrap();
        let parsed = parse(&json).unwrap();
        let items = open(&parsed, PASSWORD, &a.secret_key).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].notes, "kept");
        // No plaintext in the file.
        assert!(!String::from_utf8(json).unwrap().contains("kept"));
    }

    #[test]
    fn wrong_credentials_and_tampering_are_the_same_error() {
        let (a, file) = sample();
        let (other, _) = new_account();
        let decrypt = VaultError::Crypto(CryptoError::Decrypt);
        assert_eq!(open(&file, "wrong", &a.secret_key).unwrap_err(), decrypt);
        assert_eq!(
            open(&file, PASSWORD, &other.secret_key).unwrap_err(),
            decrypt
        );

        let mut changed = file.clone();
        changed.items[0].revision += 1;
        assert_eq!(
            open(&changed, PASSWORD, &a.secret_key).unwrap_err(),
            decrypt
        );

        let mut swapped = file.clone();
        swapped.items[0].body.0[40] ^= 1;
        assert_eq!(
            open(&swapped, PASSWORD, &a.secret_key).unwrap_err(),
            decrypt
        );

        let mut dup = file.clone();
        dup.items.push(dup.items[0].clone());
        assert_eq!(open(&dup, PASSWORD, &a.secret_key).unwrap_err(), decrypt);

        let mut params = file;
        params.kdf_params.0[1] ^= 1;
        assert!(open(&params, PASSWORD, &a.secret_key).is_err());
    }

    #[test]
    fn unknown_format_or_version_is_rejected() {
        let (_, file) = sample();
        let mut v: serde_json::Value = serde_json::to_value(&file).unwrap();
        v["version"] = 2.into();
        assert_eq!(
            parse(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
            VaultError::Invalid("this export needs a newer version of urkey")
        );
        v["format"] = "something-else".into();
        assert!(parse(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(parse(b"not json").is_err());
        let mut extra = serde_json::to_value(&file).unwrap();
        extra["plaintext"] = "x".into();
        assert!(parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    }
}
