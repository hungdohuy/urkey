//! Multi-device sync simulation against an in-memory server with the API's semantics
//! (sync.md §11.1), plus targeted integrity, resync, rollback and rotation tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashMap, HashSet};

use sync_core::vault_core::b64::{self, B64};
use sync_core::vault_core::crypto_core::ids::{AccountId, ItemId, VmkId};
use sync_core::vault_core::crypto_core::secret::VaultMasterKey;
use sync_core::vault_core::item::{Content, Item, NoteFields};
use sync_core::vault_core::record::{self, VaultKey};
use sync_core::vault_core::wire::{
    Change, ChangesResponse, PushRequest, PushResponse, PushResult, WireEvent, WireMutation,
    WireRecord,
};
use sync_core::*;

// ---------------------------------------------------------------- server model

struct Server {
    seq: u64,
    vmk_id: B64,
    keyset_version: u64,
    items: BTreeMap<String, WireRecord>,
    events: Vec<(u64, WireEvent)>,
    seen: HashMap<Vec<u8>, (WireMutation, PushResult)>,
    applied: Vec<B64>,
    horizon: u64,
}

enum PullError {
    Gone,
}

impl Server {
    fn new(vmk_id: &VmkId) -> Self {
        Self {
            seq: 0,
            vmk_id: B64(vmk_id.as_bytes().to_vec()),
            keyset_version: 1,
            items: BTreeMap::new(),
            events: Vec::new(),
            seen: HashMap::new(),
            applied: Vec::new(),
            horizon: 0,
        }
    }

    fn changes(&self, since: u64, limit: usize) -> Result<ChangesResponse, PullError> {
        if since > 0 && since < self.horizon {
            return Err(PullError::Gone);
        }
        let mut all: Vec<Change> = self
            .items
            .values()
            .filter(|r| r.seq > since)
            .map(|r| Change::Item {
                seq: r.seq,
                item: r.clone(),
            })
            .chain(
                self.events
                    .iter()
                    .filter(|(s, _)| *s > since)
                    .map(|(s, e)| Change::Event {
                        seq: *s,
                        event: e.clone(),
                    }),
            )
            .collect();
        all.sort_by_key(Change::seq);
        let has_more = all.len() > limit;
        all.truncate(limit);
        let next = all.last().map_or(since, Change::seq);
        Ok(ChangesResponse {
            vault_seq: self.seq,
            keyset_version: self.keyset_version,
            vmk_id: self.vmk_id.clone(),
            changes: all,
            next,
            has_more,
        })
    }

    fn push(&mut self, req: &PushRequest) -> PushResponse {
        let mut results = Vec::new();
        for m in &req.mutations {
            if let Some((orig, res)) = self.seen.get(&m.mutation_id.0) {
                results.push(if orig == m {
                    match res {
                        PushResult::Applied { seq } => PushResult::Duplicate { seq: *seq },
                        other => other.clone(),
                    }
                } else {
                    PushResult::Invalid {
                        code: "mutation_id_reused".into(),
                    }
                });
                continue;
            }
            let res = self.apply(m);
            self.seen
                .insert(m.mutation_id.0.clone(), (m.clone(), res.clone()));
            results.push(res);
        }
        PushResponse { results }
    }

    fn apply(&mut self, m: &WireMutation) -> PushResult {
        if m.vmk_id != self.vmk_id {
            return PushResult::KeysetChanged {
                vmk_id: self.vmk_id.clone(),
                keyset_version: self.keyset_version,
            };
        }
        if m.revision != m.base_revision + 1 {
            return PushResult::Invalid {
                code: "bad_revision".into(),
            };
        }
        let k = b64::encode(&m.item_id.0);
        match self.items.get(&k) {
            Some(cur) if cur.revision != m.base_revision => {
                return PushResult::Conflict {
                    current: cur.clone(),
                };
            }
            None if m.base_revision != 0 => {
                return PushResult::Invalid {
                    code: "unknown_item".into(),
                };
            }
            _ => {}
        }
        self.seq += 1;
        self.items.insert(
            k,
            WireRecord {
                item_id: m.item_id.clone(),
                revision: m.revision,
                seq: self.seq,
                vmk_id: m.vmk_id.clone(),
                dek_wrap: m.dek_wrap.clone(),
                body: m.body.clone(),
                deleted: m.deleted,
                updated_at: 0,
                updated_by: B64::default(),
            },
        );
        self.applied.push(m.mutation_id.clone());
        PushResult::Applied { seq: self.seq }
    }
}

// ---------------------------------------------------------------- devices

struct Device {
    state: SyncState,
    online: bool,
}

const PAGE: usize = 3;

fn pull_all(dev: &mut Device, key: &VaultKey, server: &Server) {
    loop {
        let resp = match server.changes(dev.state.cursor, PAGE) {
            Ok(r) => r,
            Err(PullError::Gone) => {
                begin_resync(&mut dev.state);
                continue;
            }
        };
        match apply_changes(&mut dev.state, key, &resp).unwrap() {
            PullOutcome::Applied(r) => {
                assert_eq!(
                    r.quarantined, 0,
                    "honest server must never trigger quarantine"
                );
                if r.done {
                    break;
                }
            }
            PullOutcome::KeysetChanged { .. } => panic!("unexpected keyset change"),
        }
    }
}

fn sync(dev: &mut Device, key: &VaultKey, server: &mut Server, lose_response: bool) {
    pull_all(dev, key, server);
    while let Some(req) = prepare_push(&mut dev.state, 2) {
        let resp = server.push(&req);
        if lose_response {
            return; // server applied; device never heard back
        }
        apply_push_results(&mut dev.state, key, &req, &resp).unwrap();
    }
    pull_all(dev, key, server);
}

fn note(marker: &str) -> Item {
    let mut i = Item::new(Content::Note(NoteFields::default()), "note", "t", "d");
    i.notes = marker.to_owned();
    i
}

fn read(key: &VaultKey, r: &record::ItemRecord) -> Option<String> {
    record::open(key, r).unwrap().item.map(|i| i.notes.clone())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn test_key() -> VaultKey {
    VaultKey {
        account_id: AccountId::from_bytes([1; 16]),
        vmk_id: VmkId::from_bytes([2; 16]),
        vmk: VaultMasterKey::generate().unwrap(),
    }
}

/// One random scenario; checks convergence, no silent loss and idempotency.
fn scenario(seed: u64, steps: usize) {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let mut rng = Rng(seed);
    let mut devs: Vec<Device> = (0..3)
        .map(|_| Device {
            state: SyncState::default(),
            online: true,
        })
        .collect();
    // marker of every content edit, by mutation id; and the latest edit per (device, item).
    let mut marker_of: HashMap<Vec<u8>, String> = HashMap::new();
    let mut latest: HashMap<(usize, String), Option<String>> = HashMap::new();
    let mut counter = 0;
    let mut trace: Vec<String> = Vec::new();

    for _ in 0..steps {
        let d = rng.below(3) as usize;
        let action = rng.below(10);
        let view = effective(&devs[d].state).unwrap();
        let editable: Vec<(String, ItemId)> = view
            .iter()
            .filter(|(_, e)| !e.conflict && !e.record.claims_deleted())
            .map(|(k, e)| (k.clone(), e.record.item_id))
            .collect();
        counter += 1;
        let marker = format!("m{counter}-d{d}");
        trace.push(format!("{counter}:d{d}:a{action}"));
        match action {
            0..=1 => {
                let out = write(&mut devs[d].state, &key, Write::Create(&note(&marker))).unwrap();
                marker_of.insert(out.mutation_id.0.clone(), marker.clone());
                latest.insert((d, b64::encode(out.item_id.as_bytes())), Some(marker));
            }
            2..=4 if !editable.is_empty() => {
                let (k, id) = &editable[rng.below(editable.len() as u64) as usize];
                let out =
                    write(&mut devs[d].state, &key, Write::Update(*id, &note(&marker))).unwrap();
                marker_of.insert(out.mutation_id.0.clone(), marker.clone());
                latest.insert((d, k.clone()), Some(marker));
            }
            5 if !editable.is_empty() => {
                let (k, id) = &editable[rng.below(editable.len() as u64) as usize];
                write(&mut devs[d].state, &key, Write::Delete(*id)).unwrap();
                latest.insert((d, k.clone()), None);
            }
            6 => devs[d].online = !devs[d].online,
            7 if devs[d].online => {
                let lose = rng.below(4) == 0;
                sync(&mut devs[d], &key, &mut server, lose);
            }
            8 => {
                // Occasionally resolve a conflict by keeping both (exercises resolution paths).
                if let Some(k) = devs[d].state.conflicts.keys().next().cloned() {
                    // Both sides must decrypt for display.
                    open_conflict(&devs[d].state, &key, &k).unwrap();
                    let out = resolve(&mut devs[d].state, &key, &k, Resolution::KeepBoth).unwrap();
                    // The local version now lives in the conflict copy; track it there.
                    latest.remove(&(d, k.clone()));
                    if let Some(out) = out {
                        let notes = read(
                            &key,
                            &record_from_mutation(&devs[d].state.outbox.last().unwrap().mutation)
                                .unwrap(),
                        );
                        if let Some(n) = notes {
                            marker_of.insert(out.mutation_id.0.clone(), n.clone());
                            latest.insert((d, b64::encode(out.item_id.as_bytes())), Some(n));
                        }
                    }
                }
            }
            _ => {
                if devs[d].online {
                    sync(&mut devs[d], &key, &mut server, false);
                }
            }
        }
    }

    // Everyone comes online and syncs until quiet.
    for _ in 0..3 {
        for dev in devs.iter_mut() {
            dev.online = true;
            sync(dev, &key, &mut server, false);
        }
    }

    // Idempotency: no mutation applied twice.
    let mut unique = HashSet::new();
    for id in &server.applied {
        assert!(
            unique.insert(id.0.clone()),
            "seed {seed}: mutation applied twice"
        );
    }

    // No silent loss: the latest content edit of each device/item is on the server or in a conflict.
    let applied_markers: HashSet<String> = server
        .applied
        .iter()
        .filter_map(|id| marker_of.get(&id.0).cloned())
        .collect();
    let mut conflict_markers = HashSet::new();
    for dev in &devs {
        for c in dev.state.conflicts.values() {
            if let Some(n) = read(&key, &record_from_mutation(&c.local).unwrap()) {
                conflict_markers.insert(n);
            }
        }
    }
    for ((d, _), m) in &latest {
        if let Some(m) = m
            && !(applied_markers.contains(m) || conflict_markers.contains(m))
        {
            {
                let ids: Vec<&Vec<u8>> = marker_of
                    .iter()
                    .filter(|(_, v)| *v == m)
                    .map(|(k, _)| k)
                    .collect();
                let server_view: Vec<String> = ids
                    .iter()
                    .map(|id| match server.seen.get(*id) {
                        Some((mu, res)) => format!(
                            "seen base={} rev={} res={:?}",
                            mu.base_revision, mu.revision, res
                        )
                        .chars()
                        .take(160)
                        .collect(),
                        None => "never reached server".into(),
                    })
                    .collect();
                let pending_left = devs.iter().any(|dv| {
                    dv.state
                        .outbox
                        .iter()
                        .any(|p| ids.contains(&&p.mutation.mutation_id.0))
                });
                let failed = devs
                    .iter()
                    .flat_map(|dv| dv.state.failed.iter())
                    .map(|f| f.code.clone())
                    .collect::<Vec<_>>();
                panic!(
                    "seed {seed}: edit {m} from device {d} was lost; server: {server_view:?}; still pending: {pending_left}; failed: {failed:?}; log: {:?}",
                    trace
                );
            }
        }
    }

    // Resolve remaining conflicts (keep server) and converge.
    for dev in devs.iter_mut() {
        let keys: Vec<String> = dev.state.conflicts.keys().cloned().collect();
        for k in keys {
            resolve(&mut dev.state, &key, &k, Resolution::KeepServer).unwrap();
        }
    }
    for _ in 0..2 {
        for dev in devs.iter_mut() {
            sync(dev, &key, &mut server, false);
        }
    }
    for (i, dev) in devs.iter().enumerate() {
        assert!(
            dev.state.outbox.is_empty(),
            "seed {seed}: device {i} still has pending edits"
        );
        assert_eq!(
            dev.state.records, server.items,
            "seed {seed}: device {i} did not converge"
        );
        assert!(dev.state.quarantine.is_empty());
    }
}

#[test]
fn single_scenario_debug() {
    if let Ok(seed) = std::env::var("URKEY_SIM_SEED") {
        scenario(seed.parse().unwrap(), 60);
    }
}

#[test]
fn random_scenarios_converge_without_loss() {
    let runs: u64 = std::env::var("URKEY_SIM_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    for seed in 0..runs {
        scenario(seed, 60);
    }
}

// ---------------------------------------------------------------- targeted tests

fn one_device_with_item(key: &VaultKey, server: &mut Server) -> (Device, ItemId) {
    let mut dev = Device {
        state: SyncState::default(),
        online: true,
    };
    let out = write(&mut dev.state, key, Write::Create(&note("v1"))).unwrap();
    sync(&mut dev, key, server, false);
    (dev, out.item_id)
}

#[test]
fn swapped_forged_and_rolled_back_records_are_quarantined() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (mut a, id) = one_device_with_item(&key, &mut server);
    write(&mut a.state, &key, Write::Create(&note("other"))).unwrap();
    sync(&mut a, &key, &mut server, false);
    let k = b64::encode(id.as_bytes());
    let good = server.items[&k].clone();

    // Body moved from another item (T-4).
    let other = server
        .items
        .values()
        .find(|r| r.item_id != good.item_id)
        .unwrap()
        .clone();
    let mut b = Device {
        state: SyncState::default(),
        online: true,
    };
    let mut swapped = good.clone();
    swapped.body = other.body.clone();
    swapped.seq = 99;
    let resp = ChangesResponse {
        vault_seq: 99,
        keyset_version: 1,
        vmk_id: server.vmk_id.clone(),
        changes: vec![Change::Item {
            seq: 99,
            item: swapped,
        }],
        next: 99,
        has_more: false,
    };
    let PullOutcome::Applied(r) = apply_changes(&mut b.state, &key, &resp).unwrap() else {
        panic!()
    };
    assert_eq!(r.quarantined, 1);
    assert!(b.state.records.is_empty());

    // Rolled back: an old revision after a newer one (T-9).
    write(&mut a.state, &key, Write::Update(id, &note("v2"))).unwrap();
    sync(&mut a, &key, &mut server, false);
    let mut old = good.clone();
    old.seq = server.seq + 1;
    let resp = ChangesResponse {
        vault_seq: server.seq + 1,
        keyset_version: 1,
        vmk_id: server.vmk_id.clone(),
        changes: vec![Change::Item {
            seq: old.seq,
            item: old,
        }],
        next: server.seq + 1,
        has_more: false,
    };
    let PullOutcome::Applied(r) = apply_changes(&mut a.state, &key, &resp).unwrap() else {
        panic!()
    };
    assert_eq!(r.quarantined, 1);
    assert_eq!(
        read(&key, &record_from_wire(&a.state.records[&k]).unwrap()).unwrap(),
        "v2"
    );

    // Forged record (wrong key).
    let mut forged_state = SyncState::default();
    let attacker = test_key();
    let (rec, _) = record::seal_new(&attacker, &note("evil")).unwrap();
    let w = WireRecord {
        item_id: B64(rec.item_id.as_bytes().to_vec()),
        revision: 1,
        seq: 1,
        vmk_id: B64(key.vmk_id.as_bytes().to_vec()),
        dek_wrap: B64(rec.dek_wrap),
        body: B64(rec.body),
        deleted: false,
        updated_at: 0,
        updated_by: B64::default(),
    };
    let resp = ChangesResponse {
        vault_seq: 1,
        keyset_version: 1,
        vmk_id: w.vmk_id.clone(),
        changes: vec![Change::Item { seq: 1, item: w }],
        next: 1,
        has_more: false,
    };
    let PullOutcome::Applied(r) = apply_changes(&mut forged_state, &key, &resp).unwrap() else {
        panic!()
    };
    assert_eq!(r.quarantined, 1);
}

#[test]
fn feed_rollback_pauses_pushing() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (mut a, id) = one_device_with_item(&key, &mut server);
    let seen = a.state.highest_vault_seq;
    write(&mut a.state, &key, Write::Update(id, &note("v2"))).unwrap();
    let resp = ChangesResponse {
        vault_seq: seen - 1,
        keyset_version: 1,
        vmk_id: server.vmk_id.clone(),
        changes: vec![],
        next: 0,
        has_more: false,
    };
    let PullOutcome::Applied(r) = apply_changes(&mut a.state, &key, &resp).unwrap() else {
        panic!()
    };
    assert!(r.rollback);
    assert!(prepare_push(&mut a.state, 10).is_none());
}

#[test]
fn resync_after_tombstone_purge_keeps_local_edits_as_conflicts() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (mut a, id) = one_device_with_item(&key, &mut server);
    let mut b = Device {
        state: SyncState::default(),
        online: true,
    };
    sync(&mut b, &key, &mut server, false);
    // B goes offline and edits; A deletes; the server purges the tombstone.
    write(&mut b.state, &key, Write::Update(id, &note("offline edit"))).unwrap();
    write(&mut a.state, &key, Write::Delete(id)).unwrap();
    sync(&mut a, &key, &mut server, false);
    let k = b64::encode(id.as_bytes());
    server.items.remove(&k);
    server.horizon = server.seq;
    server.seq += 1;
    sync(&mut b, &key, &mut server, false);
    let c = &b.state.conflicts[&k];
    assert_eq!(c.reason, ConflictReason::DeletedElsewhere);
    assert_eq!(
        read(&key, &record_from_mutation(&c.local).unwrap()).unwrap(),
        "offline edit"
    );
    // Keep local → recreated as a new item.
    resolve(&mut b.state, &key, &k, Resolution::KeepLocal).unwrap();
    sync(&mut b, &key, &mut server, false);
    assert!(
        server
            .items
            .values()
            .any(|r| read(&key, &record_from_wire(r).unwrap()).as_deref() == Some("offline edit"))
    );
}

#[test]
fn lost_push_response_is_deduplicated() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let mut a = Device {
        state: SyncState::default(),
        online: true,
    };
    write(&mut a.state, &key, Write::Create(&note("x"))).unwrap();
    let req = prepare_push(&mut a.state, 10).unwrap();
    server.push(&req); // response lost
    let req2 = prepare_push(&mut a.state, 10).unwrap();
    assert_eq!(
        req.mutations, req2.mutations,
        "a sent mutation is re-sent unchanged"
    );
    let resp = server.push(&req2);
    assert!(matches!(resp.results[0], PushResult::Duplicate { .. }));
    apply_push_results(&mut a.state, &key, &req2, &resp).unwrap();
    assert!(a.state.outbox.is_empty());
    assert_eq!(server.applied.len(), 1);
}

#[test]
fn unsent_edits_coalesce_but_sent_ones_do_not_change() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (mut a, id) = one_device_with_item(&key, &mut server);
    let first = write(&mut a.state, &key, Write::Update(id, &note("e1"))).unwrap();
    let second = write(&mut a.state, &key, Write::Update(id, &note("e2"))).unwrap();
    assert_eq!(second.replaced, Some(first.mutation_id));
    assert_eq!(a.state.outbox.len(), 1);
    let _ = prepare_push(&mut a.state, 10).unwrap(); // sent, response not yet received
    let third = write(&mut a.state, &key, Write::Update(id, &note("e3"))).unwrap();
    assert_eq!(third.replaced, None);
    assert_eq!(a.state.outbox.len(), 2);
    assert_eq!(
        a.state.outbox[1].mutation.base_revision,
        a.state.outbox[0].mutation.revision
    );
}

#[test]
fn local_delete_loses_to_remote_edit() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (mut a, id) = one_device_with_item(&key, &mut server);
    let mut b = Device {
        state: SyncState::default(),
        online: true,
    };
    sync(&mut b, &key, &mut server, false);
    write(&mut a.state, &key, Write::Update(id, &note("edited"))).unwrap();
    sync(&mut a, &key, &mut server, false);
    write(&mut b.state, &key, Write::Delete(id)).unwrap();
    sync(&mut b, &key, &mut server, false);
    let k = b64::encode(id.as_bytes());
    assert!(b.state.conflicts.is_empty());
    assert_eq!(
        read(&key, &record_from_wire(&b.state.records[&k]).unwrap()).unwrap(),
        "edited"
    );
}

#[test]
fn rotation_elsewhere_rebases_pending_edits() {
    let old = test_key();
    let mut server = Server::new(&old.vmk_id);
    let (mut a, id) = one_device_with_item(&old, &mut server);
    let (_, id2) = {
        let out = write(&mut a.state, &old, Write::Create(&note("second"))).unwrap();
        sync(&mut a, &old, &mut server, false);
        ((), out.item_id)
    };
    // Offline edits on both items, then another device rotates the VMK and edits item 2.
    write(&mut a.state, &old, Write::Update(id, &note("rebased edit"))).unwrap();
    write(
        &mut a.state,
        &old,
        Write::Update(id2, &note("conflicting edit")),
    )
    .unwrap();
    let new = VaultKey {
        account_id: old.account_id,
        vmk_id: VmkId::from_bytes([9; 16]),
        vmk: VaultMasterKey::generate().unwrap(),
    };
    let mut rotated = BTreeMap::new();
    for (k, r) in &server.items {
        let opened = record::open(&old, &record_from_wire(r).unwrap()).unwrap();
        let mut item = opened.item;
        if r.item_id.0 == id2.as_bytes() {
            item = Some(note("changed during rotation"));
        }
        let (rec, _) = record::reseal_for_rotation(
            &new,
            ItemId::from_slice(&r.item_id.0).unwrap(),
            r.revision,
            item.as_ref(),
        )
        .unwrap();
        server.seq += 1;
        rotated.insert(
            k.clone(),
            WireRecord {
                item_id: r.item_id.clone(),
                revision: rec.revision,
                seq: server.seq,
                vmk_id: B64(new.vmk_id.as_bytes().to_vec()),
                dek_wrap: B64(rec.dek_wrap),
                body: B64(rec.body),
                deleted: false,
                updated_at: 0,
                updated_by: B64::default(),
            },
        );
    }
    server.items = rotated;
    server.vmk_id = B64(new.vmk_id.as_bytes().to_vec());
    server.keyset_version += 1;

    // Device A notices, re-unlocks (gets `new`), and rebases.
    let resp = server.changes(a.state.cursor, 100).ok().unwrap();
    assert!(matches!(
        apply_changes(&mut a.state, &old, &resp).unwrap(),
        PullOutcome::KeysetChanged { .. }
    ));
    let snapshot = begin_rotation(&mut a.state, &old).unwrap();
    pull_all(&mut a, &new, &server);
    finish_rotation(&mut a.state, &new, snapshot).unwrap();
    sync(&mut a, &new, &mut server, false);

    let k1 = b64::encode(id.as_bytes());
    let k2 = b64::encode(id2.as_bytes());
    assert_eq!(
        read(&new, &record_from_wire(&server.items[&k1]).unwrap()).unwrap(),
        "rebased edit"
    );
    let c = &a.state.conflicts[&k2];
    assert_eq!(c.reason, ConflictReason::KeysChanged);
    assert_eq!(
        read(&new, &record_from_mutation(&c.local).unwrap()).unwrap(),
        "conflicting edit"
    );
}

#[test]
fn state_round_trips_through_json() {
    let key = test_key();
    let mut server = Server::new(&key.vmk_id);
    let (a, _) = one_device_with_item(&key, &mut server);
    let json = serde_json::to_string(&a.state).unwrap();
    let back: SyncState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a.state);
}
