//! Agent state: keys in memory, each with an optional expiry.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use vault_core::ssh::AgentKey;

use crate::protocol::{self, Request, msg};

struct Entry {
    key: AgentKey,
    blob: Vec<u8>,
    expires: Option<Instant>,
}

/// The agent. Keys are wiped (by `ssh-key`) when removed, expired or dropped.
#[derive(Default)]
pub struct Agent {
    keys: Mutex<Vec<Entry>>,
}

impl core::fmt::Debug for Agent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Agent").finish_non_exhaustive()
    }
}

fn failure() -> Vec<u8> {
    vec![msg::FAILURE]
}

impl Agent {
    /// A new, empty agent.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_keys<T>(&self, f: impl FnOnce(&mut Vec<Entry>) -> T) -> T {
        let mut guard = match self.keys.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        guard.retain(|e| e.expires.is_none_or(|t| t > now));
        f(&mut guard)
    }

    /// Drops expired keys (also done on every request).
    pub fn purge_expired(&self) {
        self.with_keys(|_| ());
    }

    /// Number of loaded keys.
    pub fn len(&self) -> usize {
        self.with_keys(|k| k.len())
    }

    /// Whether no keys are loaded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Handles one request payload and returns the response payload.
    pub fn handle(&self, payload: &[u8]) -> Vec<u8> {
        let Ok(req) = protocol::parse_request(payload) else {
            return failure();
        };
        match req {
            Request::List => self.with_keys(|keys| {
                let ids: Vec<(Vec<u8>, String)> = keys
                    .iter()
                    .map(|e| (e.blob.clone(), e.key.comment().to_owned()))
                    .collect();
                protocol::identities_answer(&ids)
            }),
            Request::Sign { key_blob, data, .. } => self.with_keys(|keys| {
                match keys
                    .iter()
                    .find(|e| e.blob == key_blob)
                    .map(|e| e.key.sign(&data))
                {
                    Some(Ok(sig)) => protocol::sign_response(&sig),
                    _ => failure(),
                }
            }),
            Request::Add {
                key,
                lifetime,
                confirm,
            } => {
                if confirm {
                    // Per-use confirmation needs the native UI (R-SSH-5, V1.1); refuse rather than ignore.
                    return failure();
                }
                let comment = key.comment().as_str_lossy().to_owned();
                let Ok(agent_key) = AgentKey::from_private_key(*key, comment) else {
                    return failure();
                };
                let Ok(blob) = agent_key.public_key_blob() else {
                    return failure();
                };
                let expires = lifetime.map(|s| Instant::now() + Duration::from_secs(u64::from(s)));
                self.with_keys(|keys| {
                    keys.retain(|e| e.blob != blob);
                    keys.push(Entry {
                        key: agent_key,
                        blob,
                        expires,
                    });
                });
                vec![msg::SUCCESS]
            }
            Request::Remove { key_blob } => self.with_keys(|keys| {
                let before = keys.len();
                keys.retain(|e| e.blob != key_blob);
                if keys.len() < before {
                    vec![msg::SUCCESS]
                } else {
                    failure()
                }
            }),
            Request::RemoveAll => self.with_keys(|keys| {
                keys.clear();
                vec![msg::SUCCESS]
            }),
            Request::Unsupported(_) => failure(),
        }
    }
}
