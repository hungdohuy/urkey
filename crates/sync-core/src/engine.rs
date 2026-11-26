//! The sync engine (sync.md §2–§8).

use std::collections::BTreeMap;

use vault_core::b64::{self, B64};
use vault_core::crypto_core::ids::{DeviceId, ItemId, VmkId};
use vault_core::item::Item;
use vault_core::record::{self, ItemRecord, VaultKey};
use vault_core::wire::{
    Change, ChangesResponse, PushRequest, PushResponse, PushResult, WireMutation, WireRecord,
};
use vault_core::{Result, VaultError};

use crate::state::{
    Conflict, ConflictReason, Failed, Pending, Quarantined, StoredEvent, SyncState,
};

/// Maximum mutations per push request (data-model §5).
pub const MAX_PUSH: usize = 100;

fn key_of(id: &ItemId) -> String {
    b64::encode(id.as_bytes())
}

fn random_id() -> Result<B64> {
    Ok(B64(DeviceId::generate()
        .map_err(VaultError::from)?
        .as_bytes()
        .to_vec()))
}

/// Converts a wire record into a typed record.
pub fn record_from_wire(w: &WireRecord) -> Result<ItemRecord> {
    Ok(ItemRecord {
        item_id: ItemId::from_slice(&w.item_id.0)?,
        revision: w.revision,
        vmk_id: VmkId::from_slice(&w.vmk_id.0)?,
        dek_wrap: w.dek_wrap.0.clone(),
        body: w.body.0.clone(),
    })
}

/// Converts a pending mutation into a typed record.
pub fn record_from_mutation(m: &WireMutation) -> Result<ItemRecord> {
    Ok(ItemRecord {
        item_id: ItemId::from_slice(&m.item_id.0)?,
        revision: m.revision,
        vmk_id: VmkId::from_slice(&m.vmk_id.0)?,
        dek_wrap: m.dek_wrap.0.clone(),
        body: m.body.0.clone(),
    })
}

fn mutation_from_record(r: &ItemRecord, base_revision: u64, mutation_id: B64) -> WireMutation {
    WireMutation {
        mutation_id,
        item_id: B64(r.item_id.as_bytes().to_vec()),
        base_revision,
        revision: r.revision,
        vmk_id: B64(r.vmk_id.as_bytes().to_vec()),
        dek_wrap: B64(r.dek_wrap.clone()),
        body: B64(r.body.clone()),
        deleted: r.claims_deleted(),
    }
}

/// What this device currently shows for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Latest local version (pending edit if any, else the server record).
    pub record: ItemRecord,
    /// Has unsynced local edits.
    pub pending: bool,
    /// Has an unresolved conflict.
    pub conflict: bool,
}

/// A local change.
#[derive(Debug)]
pub enum Write<'a> {
    /// New item.
    Create(&'a Item),
    /// New version of an item (also restores a deleted item).
    Update(ItemId, &'a Item),
    /// Delete an item.
    Delete(ItemId),
}

/// Result of a local change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Item written.
    pub item_id: ItemId,
    /// Id of the new pending mutation.
    pub mutation_id: B64,
    /// An unsent pending mutation this one replaced (sync.md §4).
    pub replaced: Option<B64>,
}

/// Summary of one applied pull page.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PullReport {
    /// Records stored.
    pub applied: usize,
    /// Records refused (integrity problems).
    pub quarantined: usize,
    /// New conflicts.
    pub conflicts: usize,
    /// Local deletes dropped because the item was edited elsewhere (shown as info).
    pub deletes_overridden: usize,
    /// Events received.
    pub events: usize,
    /// No more pages.
    pub done: bool,
    /// The server returned older data than this device saw before (sync.md §7).
    pub rollback: bool,
}

/// Outcome of applying a pull page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// Page applied (see report).
    Applied(PullReport),
    /// The VMK changed on another device: unlock again, then [`begin_rotation`].
    KeysetChanged {
        /// New VMK generation.
        vmk_id: B64,
    },
}

/// Summary of push results.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PushReport {
    /// Accepted (or already accepted).
    pub applied: usize,
    /// Became conflicts.
    pub conflicts: usize,
    /// Refused as invalid.
    pub invalid: usize,
    /// The VMK changed: stop, unlock again, rotate.
    pub keyset_changed: bool,
}

/// The current revision of an item as this device sees it (0 if unknown).
pub fn current_revision(state: &SyncState, item: &str) -> u64 {
    state
        .outbox
        .iter()
        .rev()
        .find(|p| b64::encode(&p.mutation.item_id.0) == item)
        .map(|p| p.mutation.revision)
        .or_else(|| state.records.get(item).map(|r| r.revision))
        .unwrap_or(0)
}

/// Latest local version of every item.
pub fn effective(state: &SyncState) -> Result<BTreeMap<String, Effective>> {
    let mut out = BTreeMap::new();
    for (k, w) in &state.records {
        out.insert(
            k.clone(),
            Effective {
                record: record_from_wire(w)?,
                pending: false,
                conflict: state.conflicts.contains_key(k),
            },
        );
    }
    for p in &state.outbox {
        let k = b64::encode(&p.mutation.item_id.0);
        let conflict = state.conflicts.contains_key(&k);
        out.insert(
            k,
            Effective {
                record: record_from_mutation(&p.mutation)?,
                pending: true,
                conflict,
            },
        );
    }
    for (k, c) in &state.conflicts {
        if !out.contains_key(k)
            && let Some(server) = &c.server
        {
            out.insert(
                k.clone(),
                Effective {
                    record: record_from_wire(server)?,
                    pending: false,
                    conflict: true,
                },
            );
        }
    }
    Ok(out)
}

/// Applies a local change: seals it and queues it in the outbox following sync.md §4.
pub fn write(state: &mut SyncState, key: &VaultKey, change: Write<'_>) -> Result<WriteOutcome> {
    let mutation_id = random_id()?;
    if let Write::Create(item) = change {
        let (rec, _) = record::seal_new(key, item)?;
        state.outbox.push(Pending {
            mutation: mutation_from_record(&rec, 0, mutation_id.clone()),
            sent: false,
            attempts: 0,
        });
        return Ok(WriteOutcome {
            item_id: rec.item_id,
            mutation_id,
            replaced: None,
        });
    }
    let (item_id, item) = match change {
        Write::Update(id, item) => (id, Some(item)),
        Write::Delete(id) => (id, None),
        Write::Create(_) => unreachable!(),
    };
    let k = key_of(&item_id);
    if state.conflicts.contains_key(&k) {
        return Err(VaultError::Invalid(
            "resolve the conflict on this item first",
        ));
    }
    let last_idx = state
        .outbox
        .iter()
        .rposition(|p| b64::encode(&p.mutation.item_id.0) == k);
    // Coalesce into an unsent pending edit; never alter one that may have reached the server.
    let (base, replaces) = match last_idx {
        Some(i) if !state.outbox[i].sent => (state.outbox[i].mutation.base_revision, Some(i)),
        Some(i) => (state.outbox[i].mutation.revision, None),
        None => (
            state
                .records
                .get(&k)
                .map(|r| r.revision)
                .ok_or(VaultError::Invalid("unknown item"))?,
            None,
        ),
    };
    // Any version of the item gives the item key (all are under the current VMK).
    let any = match last_idx {
        Some(i) => record_from_mutation(&state.outbox[i].mutation)?,
        None => record_from_wire(
            state
                .records
                .get(&k)
                .ok_or(VaultError::Invalid("unknown item"))?,
        )?,
    };
    let item_key = record::open(key, &any)?.item_key;
    let rec = match item {
        Some(item) => record::seal_update(key, item_id, &item_key, base, item)?,
        None => record::seal_delete(key, item_id, &item_key, base)?,
    };
    let pending = Pending {
        mutation: mutation_from_record(&rec, base, mutation_id.clone()),
        sent: false,
        attempts: 0,
    };
    let replaced = match replaces {
        Some(i) => Some(
            std::mem::replace(&mut state.outbox[i], pending)
                .mutation
                .mutation_id,
        ),
        None => {
            state.outbox.push(pending);
            None
        }
    };
    Ok(WriteOutcome {
        item_id,
        mutation_id,
        replaced,
    })
}

fn quarantine(state: &mut SyncState, seq: u64, item: &str, reason: &str) {
    state.quarantine.push(Quarantined {
        seq,
        item_id: item.to_owned(),
        reason: reason.to_owned(),
    });
}

/// Verifies and stores a server record. Returns false (and quarantines) if it fails sync.md §7.
fn accept_record(state: &mut SyncState, key: &VaultKey, seq: u64, w: &WireRecord) -> bool {
    let k = b64::encode(&w.item_id.0);
    let known = state.known_revisions.get(&k).copied().unwrap_or(0);
    if w.revision < known {
        quarantine(state, seq, &k, "rollback");
        return false;
    }
    if w.revision == known
        && let Some(existing) = state.records.get(&k)
        && (existing.body != w.body || existing.dek_wrap != w.dek_wrap)
    {
        quarantine(state, seq, &k, "revision_reused");
        return false;
    }
    let ok = record_from_wire(w)
        .and_then(|r| record::open(key, &r))
        .is_ok();
    if !ok {
        quarantine(state, seq, &k, "decrypt_failed");
        return false;
    }
    state.records.insert(k.clone(), w.clone());
    state.known_revisions.insert(k, w.revision.max(known));
    true
}

/// Reconciles pending edits of one item with the server's current record.
fn reconcile(state: &mut SyncState, key: &VaultKey, server: &WireRecord, report: &mut PullReport) {
    let k = b64::encode(&server.item_id.0);
    let mine: Vec<usize> = (0..state.outbox.len())
        .filter(|&i| b64::encode(&state.outbox[i].mutation.item_id.0) == k)
        .collect();
    if mine.is_empty() {
        return;
    }
    // Our own edit came back: drop it and everything before it for this item.
    if let Some(&ack) = mine.iter().find(|&&i| {
        let m = &state.outbox[i].mutation;
        m.revision == server.revision && m.body == server.body
    }) {
        let ack_rev = state.outbox[ack].mutation.revision;
        state.outbox.retain(|p| {
            !(b64::encode(&p.mutation.item_id.0) == k && p.mutation.revision <= ack_rev)
        });
        return;
    }
    let first = &state.outbox[mine[0]].mutation;
    if first.base_revision >= server.revision {
        return; // still applies on top of the server version
    }
    // Conflict: the server moved past what our edits were based on (sync.md §6.2).
    let latest = state.outbox[*mine.last().unwrap_or(&mine[0])]
        .mutation
        .clone();
    state
        .outbox
        .retain(|p| b64::encode(&p.mutation.item_id.0) != k);
    if latest.deleted {
        // Local delete vs remote edit: the edit wins; local delete dropped (info only).
        report.deletes_overridden += 1;
        return;
    }
    // The record was verified by `accept_record` with `key`, so its kind byte is authentic.
    let _ = key;
    let server_deleted = record_from_wire(server).is_ok_and(|r| r.claims_deleted());
    state.conflicts.insert(
        k,
        Conflict {
            server: Some(server.clone()),
            local: latest,
            reason: if server_deleted {
                ConflictReason::DeletedElsewhere
            } else {
                ConflictReason::EditedElsewhere
            },
        },
    );
    report.conflicts += 1;
}

/// Applies one page of `GET /v1/sync/changes` (sync.md §7, §10 step 1).
pub fn apply_changes(
    state: &mut SyncState,
    key: &VaultKey,
    resp: &ChangesResponse,
) -> Result<PullOutcome> {
    let mut report = PullReport {
        done: !resp.has_more,
        ..Default::default()
    };
    if resp.vault_seq < state.highest_vault_seq || resp.keyset_version < state.keyset_version {
        state.rollback_warning = true;
        report.rollback = true;
        return Ok(PullOutcome::Applied(report));
    }
    if resp.vmk_id.0 != key.vmk_id.as_bytes() {
        return Ok(PullOutcome::KeysetChanged {
            vmk_id: resp.vmk_id.clone(),
        });
    }
    for change in &resp.changes {
        if change.seq() <= state.cursor {
            continue; // already applied (or out of order): never move backwards
        }
        match change {
            Change::Event { seq, event } => {
                state.events.push(StoredEvent {
                    seq: *seq,
                    event: event.clone(),
                    acknowledged: false,
                });
                report.events += 1;
            }
            Change::Item { seq, item } => {
                if accept_record(state, key, *seq, item) {
                    report.applied += 1;
                    reconcile(state, key, item, &mut report);
                } else {
                    report.quarantined += 1;
                }
            }
        }
    }
    state.cursor = state.cursor.max(resp.next);
    state.highest_vault_seq = state.highest_vault_seq.max(resp.vault_seq);
    state.keyset_version = state.keyset_version.max(resp.keyset_version);
    if report.done && state.resyncing {
        finish_resync(state);
    }
    Ok(PullOutcome::Applied(report))
}

/// Starts a full resync after `410 resync_required` (sync.md §8.1). Pending edits are kept.
pub fn begin_resync(state: &mut SyncState) {
    state.resyncing = true;
    state.cursor = 0;
    state.records.clear();
}

fn finish_resync(state: &mut SyncState) {
    state.resyncing = false;
    let missing: Vec<String> = state
        .outbox
        .iter()
        .filter(|p| p.mutation.base_revision > 0)
        .map(|p| b64::encode(&p.mutation.item_id.0))
        .filter(|k| !state.records.contains_key(k))
        .collect();
    for k in missing {
        let latest = state
            .outbox
            .iter()
            .rev()
            .find(|p| b64::encode(&p.mutation.item_id.0) == k)
            .map(|p| p.mutation.clone());
        state
            .outbox
            .retain(|p| b64::encode(&p.mutation.item_id.0) != k);
        if let Some(local) = latest.filter(|m| !m.deleted) {
            state.conflicts.insert(
                k,
                Conflict {
                    server: None,
                    local,
                    reason: ConflictReason::DeletedElsewhere,
                },
            );
        }
    }
}

/// Prepares the next `POST /v1/sync/push` (oldest first). `None` if nothing to send or pushing is
/// paused by a rollback warning.
pub fn prepare_push(state: &mut SyncState, max: usize) -> Option<PushRequest> {
    if state.rollback_warning || state.outbox.is_empty() {
        return None;
    }
    let n = state.outbox.len().min(max.clamp(1, MAX_PUSH));
    let mutations = state.outbox[..n]
        .iter_mut()
        .map(|p| {
            p.sent = true;
            p.attempts += 1;
            p.mutation.clone()
        })
        .collect();
    Some(PushRequest { mutations })
}

/// Applies the response to a push (sync.md §3.3, §5, §6).
pub fn apply_push_results(
    state: &mut SyncState,
    key: &VaultKey,
    req: &PushRequest,
    resp: &PushResponse,
) -> Result<PushReport> {
    let mut report = PushReport::default();
    let mut pull = PullReport::default();
    for (m, result) in req.mutations.iter().zip(&resp.results) {
        let Some(idx) = state
            .outbox
            .iter()
            .position(|p| p.mutation.mutation_id == m.mutation_id)
        else {
            continue; // already resolved
        };
        match result {
            PushResult::Applied { seq } | PushResult::Duplicate { seq } => {
                let p = state.outbox.remove(idx);
                let k = b64::encode(&p.mutation.item_id.0);
                let known = state.known_revisions.get(&k).copied().unwrap_or(0);
                if p.mutation.revision > known {
                    let w = WireRecord {
                        item_id: p.mutation.item_id.clone(),
                        revision: p.mutation.revision,
                        seq: *seq,
                        vmk_id: p.mutation.vmk_id.clone(),
                        dek_wrap: p.mutation.dek_wrap.clone(),
                        body: p.mutation.body.clone(),
                        deleted: p.mutation.deleted,
                        updated_at: 0,
                        updated_by: B64::default(),
                    };
                    state.records.insert(k.clone(), w);
                    state.known_revisions.insert(k, p.mutation.revision);
                }
                report.applied += 1;
            }
            PushResult::Conflict { current } => {
                if accept_record(state, key, current.seq, current) {
                    let before = state.conflicts.len();
                    reconcile(state, key, current, &mut pull);
                    report.conflicts += state.conflicts.len() - before;
                }
            }
            PushResult::KeysetChanged { .. } => report.keyset_changed = true,
            PushResult::Invalid { code } => {
                let p = state.outbox.remove(idx);
                state.failed.push(Failed {
                    mutation: p.mutation,
                    code: code.clone(),
                });
                report.invalid += 1;
            }
        }
    }
    Ok(report)
}

/// The user's choice for a conflict (sync.md §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Keep the other device's version.
    KeepServer,
    /// Keep this device's version (written as a new revision on top).
    KeepLocal,
    /// Keep both: this device's version becomes a new item marked `conflict_of`.
    KeepBoth,
}

/// Decrypts the two sides of a conflict for display. `None` means deleted / absent.
pub fn open_conflict(
    state: &SyncState,
    key: &VaultKey,
    item: &str,
) -> Result<(Option<Item>, Option<Item>)> {
    let c = state
        .conflicts
        .get(item)
        .ok_or(VaultError::Invalid("no such conflict"))?;
    let server = match &c.server {
        Some(w) => record::open(key, &record_from_wire(w)?)?.item,
        None => None,
    };
    let local = record::open(key, &record_from_mutation(&c.local)?)?.item;
    Ok((server, local))
}

/// Resolves a conflict.
pub fn resolve(
    state: &mut SyncState,
    key: &VaultKey,
    item: &str,
    choice: Resolution,
) -> Result<Option<WriteOutcome>> {
    let (_, local) = open_conflict(state, key, item)?;
    let c = state
        .conflicts
        .remove(item)
        .ok_or(VaultError::Invalid("no such conflict"))?;
    let item_id = ItemId::from_slice(&c.local.item_id.0)?;
    match (choice, local) {
        (Resolution::KeepServer, _) | (_, None) => Ok(None),
        (Resolution::KeepLocal, Some(local)) => {
            if c.server.is_some() {
                write(state, key, Write::Update(item_id, &local)).map(Some)
            } else {
                write(state, key, Write::Create(&local)).map(Some)
            }
        }
        (Resolution::KeepBoth, Some(mut local)) => {
            local.conflict_of = Some(item.to_owned());
            if !local.title.ends_with("(conflict copy)") {
                local.title = format!("{} (conflict copy)", local.title.trim());
                if local.title.chars().count() > 200 {
                    local.title = local.title.chars().take(200).collect();
                }
            }
            write(state, key, Write::Create(&local)).map(Some)
        }
    }
}

/// Plaintext kept in memory between [`begin_rotation`] and [`finish_rotation`].
pub struct RotationSnapshot {
    items: Vec<SnapshotItem>,
}

struct SnapshotItem {
    key: String,
    /// Server content the local edit was based on (old key).
    base: Option<Item>,
    /// Local content (`None` = local delete).
    local: Option<Item>,
    /// The item was already in conflict before the rotation.
    was_conflict: bool,
}

impl core::fmt::Debug for RotationSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RotationSnapshot({} items)", self.items.len())
    }
}

/// Starts handling a VMK rotation done on another device (sync.md §8.4). Decrypts pending edits and
/// conflicts with the **old** key, then clears server records for a full pull with the new key.
pub fn begin_rotation(state: &mut SyncState, old_key: &VaultKey) -> Result<RotationSnapshot> {
    let mut keys: Vec<String> = state
        .outbox
        .iter()
        .map(|p| b64::encode(&p.mutation.item_id.0))
        .collect();
    keys.extend(state.conflicts.keys().cloned());
    keys.sort();
    keys.dedup();
    let mut items = Vec::new();
    for k in keys {
        let base = match state.records.get(&k) {
            Some(w) => record::open(old_key, &record_from_wire(w)?)?.item,
            None => None,
        };
        let pending = state
            .outbox
            .iter()
            .rev()
            .find(|p| b64::encode(&p.mutation.item_id.0) == k);
        let (local, was_conflict) = match (pending, state.conflicts.get(&k)) {
            (Some(p), _) => (
                record::open(old_key, &record_from_mutation(&p.mutation)?)?.item,
                false,
            ),
            (None, Some(c)) => (
                record::open(old_key, &record_from_mutation(&c.local)?)?.item,
                true,
            ),
            (None, None) => continue,
        };
        items.push(SnapshotItem {
            key: k,
            base,
            local,
            was_conflict,
        });
    }
    state.outbox.clear();
    state.conflicts.clear();
    begin_resync(state);
    Ok(RotationSnapshot { items })
}

/// Finishes a rotation after the full pull with the new key: edits based on unchanged content
/// are re-sealed and kept pending; anything else becomes a conflict (never dropped).
pub fn finish_rotation(
    state: &mut SyncState,
    new_key: &VaultKey,
    snapshot: RotationSnapshot,
) -> Result<()> {
    for SnapshotItem {
        key: k,
        base,
        local,
        was_conflict,
    } in snapshot.items
    {
        let item_id = ItemId::from_slice(&b64::decode(&k)?)?;
        let server = state.records.get(&k).cloned();
        let server_item = match &server {
            Some(w) => record::open(new_key, &record_from_wire(w)?)?.item,
            None => None,
        };
        let unchanged = server.is_some() && base.is_some() && server_item == base && !was_conflict;
        match (local, unchanged) {
            (Some(local), true) => {
                write(state, new_key, Write::Update(item_id, &local))?;
            }
            (None, true) => {
                write(state, new_key, Write::Delete(item_id))?;
            }
            (Some(local), false) => {
                // Seal the local version under the new key so it can be shown and resolved.
                let rec = match &server {
                    Some(w) => {
                        let item_key = record::open(new_key, &record_from_wire(w)?)?.item_key;
                        record::seal_update(new_key, item_id, &item_key, w.revision, &local)?
                    }
                    None => record::seal_new(new_key, &local)?.0,
                };
                let reason = if server.is_some() {
                    ConflictReason::KeysChanged
                } else {
                    ConflictReason::DeletedElsewhere
                };
                let base_rev = server.as_ref().map_or(0, |w| w.revision);
                state.conflicts.insert(
                    k,
                    Conflict {
                        server,
                        local: mutation_from_record(&rec, base_rev, random_id()?),
                        reason,
                    },
                );
            }
            (None, false) => {}
        }
    }
    Ok(())
}
