//! Persisted sync state (one document per account; data-model §4, see change log there).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use vault_core::wire::{WireEvent, WireMutation, WireRecord};

/// Key type for maps: the base64url item id.
pub type ItemKeyStr = String;

/// A local edit waiting for the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The mutation exactly as it will be (re)sent.
    pub mutation: WireMutation,
    /// Sent at least once: its content must never change again (sync.md §4).
    pub sent: bool,
    /// Send attempts.
    pub attempts: u32,
}

/// Why a conflict exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    /// Edited on two devices.
    EditedElsewhere,
    /// Deleted on another device while edited here.
    DeletedElsewhere,
    /// The vault key changed and the content differs.
    KeysChanged,
}

/// A local version that lost to the server version and awaits the user's choice (sync.md §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The server's current record (`None` if the item no longer exists on the server).
    pub server: Option<WireRecord>,
    /// This device's version (sealed under the VMK generation in `local.vmk_id`).
    pub local: WireMutation,
    /// Why.
    pub reason: ConflictReason,
}

/// A pulled record that failed verification and was not applied (sync.md §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantined {
    /// Feed position.
    pub seq: u64,
    /// Item.
    pub item_id: ItemKeyStr,
    /// `decrypt_failed`, `rollback` or `revision_reused`.
    pub reason: String,
}

/// A mutation the server refused as invalid; kept so the user can see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failed {
    /// The mutation.
    pub mutation: WireMutation,
    /// Server code.
    pub code: String,
}

/// A security event seen in the feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Feed position.
    pub seq: u64,
    /// Event.
    pub event: WireEvent,
    /// Dismissed by the user.
    pub acknowledged: bool,
}

/// Everything the engine persists for one account on one device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Last applied feed position (only advanced by pulls).
    pub cursor: u64,
    /// Highest `vault_seq` ever seen (rollback detection).
    pub highest_vault_seq: u64,
    /// Highest keyset version seen.
    pub keyset_version: u64,
    /// Latest verified server record per item.
    pub records: BTreeMap<ItemKeyStr, WireRecord>,
    /// Highest verified revision per item (survives resync).
    pub known_revisions: BTreeMap<ItemKeyStr, u64>,
    /// Local edits, oldest first.
    pub outbox: Vec<Pending>,
    /// Unresolved conflicts per item.
    pub conflicts: BTreeMap<ItemKeyStr, Conflict>,
    /// Records that failed verification.
    pub quarantine: Vec<Quarantined>,
    /// Mutations refused as invalid.
    pub failed: Vec<Failed>,
    /// Security events.
    pub events: Vec<StoredEvent>,
    /// Set when the server returned older data than seen before; pushing stops until cleared.
    pub rollback_warning: bool,
    /// Set while a full resync is in progress.
    pub resyncing: bool,
}
