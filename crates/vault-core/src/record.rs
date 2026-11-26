//! Encrypted item records (data-model §2) and the operations that produce and open them
//! (crypto design §7.2). A record never contains plaintext.

use crypto_core::CryptoError;
use crypto_core::container::{self, ItemContent, Kind};
use crypto_core::ids::{AccountId, ItemId, VmkId};
use crypto_core::secret::{ItemKey, VaultMasterKey};

use crate::item::Item;
use crate::{Result, VaultError};

/// The unlocked vault key and its identity.
pub struct VaultKey {
    /// Account.
    pub account_id: AccountId,
    /// Current VMK generation.
    pub vmk_id: VmkId,
    /// The VMK itself.
    pub vmk: VaultMasterKey,
}

impl core::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultKey")
            .field("vmk_id", &self.vmk_id)
            .finish_non_exhaustive()
    }
}

/// One item's latest encrypted state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRecord {
    /// Item.
    pub item_id: ItemId,
    /// Revision bound into the ciphertext's AAD.
    pub revision: u64,
    /// VMK generation that wraps the item key.
    pub vmk_id: VmkId,
    /// Container kind 0x03.
    pub dek_wrap: Vec<u8>,
    /// Container kind 0x04 (payload) or 0x05 (tombstone).
    pub body: Vec<u8>,
}

impl ItemRecord {
    /// Whether the body claims to be a tombstone (unauthenticated hint; open to be sure).
    pub fn claims_deleted(&self) -> bool {
        container::peek_header(&self.body).is_ok_and(|h| h.kind == Kind::Tombstone)
    }
}

/// A verified, decrypted record.
pub struct Opened {
    /// The item key (needed to write the next revision).
    pub item_key: ItemKey,
    /// The item, or `None` if the record is an authenticated tombstone.
    pub item: Option<Item>,
}

impl core::fmt::Debug for Opened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opened")
            .field("deleted", &self.item.is_none())
            .finish_non_exhaustive()
    }
}

/// Opens and verifies a record (sync.md §7 steps 1–2). A record wrapped under another VMK
/// generation, or failing any check, is a decryption error.
pub fn open(key: &VaultKey, record: &ItemRecord) -> Result<Opened> {
    if record.vmk_id != key.vmk_id {
        return Err(CryptoError::Decrypt.into());
    }
    let item_key = container::unwrap_item_key(
        &key.vmk,
        key.vmk_id,
        &record.dek_wrap,
        key.account_id,
        record.item_id,
    )?;
    let item = match container::open_item(
        &item_key,
        key.account_id,
        record.item_id,
        record.revision,
        &record.body,
    )? {
        ItemContent::Body(body) => {
            Some(Item::from_json(&body).map_err(|_| VaultError::Crypto(CryptoError::Decrypt))?)
        }
        ItemContent::Deleted => None,
    };
    Ok(Opened { item_key, item })
}

fn seal(
    key: &VaultKey,
    item_id: ItemId,
    item_key: &ItemKey,
    revision: u64,
    item: Option<&Item>,
) -> Result<ItemRecord> {
    let dek_wrap =
        container::wrap_item_key(&key.vmk, key.vmk_id, item_key, key.account_id, item_id)?;
    let body = match item {
        Some(item) => container::seal_item(
            item_key,
            key.account_id,
            item_id,
            revision,
            &item.to_json()?,
        )?,
        None => container::seal_tombstone(item_key, key.account_id, item_id, revision)?,
    };
    Ok(ItemRecord {
        item_id,
        revision,
        vmk_id: key.vmk_id,
        dek_wrap,
        body,
    })
}

/// Encrypts a new item as revision 1 with a fresh item id and item key.
pub fn seal_new(key: &VaultKey, item: &Item) -> Result<(ItemRecord, ItemKey)> {
    let item_id = ItemId::generate()?;
    let item_key = ItemKey::generate()?;
    let record = seal(key, item_id, &item_key, 1, Some(item))?;
    Ok((record, item_key))
}

/// Encrypts the next revision of an existing item.
pub fn seal_update(
    key: &VaultKey,
    item_id: ItemId,
    item_key: &ItemKey,
    base_revision: u64,
    item: &Item,
) -> Result<ItemRecord> {
    if !item.is_editable() {
        return Err(VaultError::UnsupportedSchema);
    }
    seal(key, item_id, item_key, base_revision + 1, Some(item))
}

/// Encrypts an authenticated deletion as the next revision.
pub fn seal_delete(
    key: &VaultKey,
    item_id: ItemId,
    item_key: &ItemKey,
    base_revision: u64,
) -> Result<ItemRecord> {
    seal(key, item_id, item_key, base_revision + 1, None)
}

/// Re-encrypts an opened item under a new VMK with a new item key, as the next revision
/// (VMK rotation, crypto design §7.10). Content is unchanged.
pub fn reseal_for_rotation(
    new_key: &VaultKey,
    item_id: ItemId,
    base_revision: u64,
    item: Option<&Item>,
) -> Result<(ItemRecord, ItemKey)> {
    let item_key = ItemKey::generate()?;
    let record = seal(new_key, item_id, &item_key, base_revision + 1, item)?;
    Ok((record, item_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Content, NoteFields};

    fn key() -> VaultKey {
        VaultKey {
            account_id: AccountId::from_bytes([1; 16]),
            vmk_id: VmkId::from_bytes([2; 16]),
            vmk: VaultMasterKey::generate().unwrap(),
        }
    }

    fn note() -> Item {
        let mut i = Item::new(Content::Note(NoteFields::default()), "Note", "t", "d");
        i.notes = "secret text".into();
        i
    }

    #[test]
    fn create_update_delete_cycle() {
        let k = key();
        let (r1, dek) = seal_new(&k, &note()).unwrap();
        assert_eq!(r1.revision, 1);
        let o = open(&k, &r1).unwrap();
        assert_eq!(o.item.unwrap().notes, "secret text");
        let mut edited = note();
        edited.notes = "changed".into();
        let r2 = seal_update(&k, r1.item_id, &dek, 1, &edited).unwrap();
        assert_eq!(r2.revision, 2);
        assert_eq!(open(&k, &r2).unwrap().item.unwrap().notes, "changed");
        let r3 = seal_delete(&k, r1.item_id, &dek, 2).unwrap();
        assert!(r3.claims_deleted());
        assert!(open(&k, &r3).unwrap().item.is_none());
    }

    #[test]
    fn no_plaintext_in_records() {
        let k = key();
        let (r, _) = seal_new(&k, &note()).unwrap();
        let hay = [r.dek_wrap.as_slice(), r.body.as_slice()].concat();
        assert!(!hay.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn records_are_bound_to_item_revision_and_vmk() {
        let k = key();
        let (r, _) = seal_new(&k, &note()).unwrap();
        let mut moved = r.clone();
        moved.item_id = ItemId::from_bytes([9; 16]);
        assert!(open(&k, &moved).is_err());
        let mut rolled = r.clone();
        rolled.revision = 2;
        assert!(open(&k, &rolled).is_err());
        let other = VaultKey {
            vmk_id: VmkId::from_bytes([3; 16]),
            ..key()
        };
        assert!(open(&other, &r).is_err());
    }

    #[test]
    fn read_only_items_cannot_be_updated() {
        let k = key();
        let (r, dek) = seal_new(&k, &note()).unwrap();
        let ro = Item::from_json(br#"{"schema":5,"type":"note","title":"x"}"#).unwrap();
        assert_eq!(
            seal_update(&k, r.item_id, &dek, 1, &ro).unwrap_err(),
            VaultError::UnsupportedSchema
        );
    }
}
