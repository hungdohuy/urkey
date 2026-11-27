//! Item plaintext (data-model §1): the JSON inside an encrypted item payload.
//!
//! Unknown keys are preserved at the top level and inside `fields`, so editing an item written by
//! a newer client never drops data. Bodies with a newer `schema` are read-only; unknown `type`s are
//! kept verbatim as [`Content::Unknown`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::{Result, VaultError};

/// Highest item body schema this client can write.
pub const SCHEMA: u32 = 1;

/// A decrypted vault item.
#[derive(Clone, PartialEq)]
pub struct Item {
    /// Body schema version.
    pub schema: u32,
    /// Type-specific content.
    pub content: Content,
    /// 1..=200 characters.
    pub title: String,
    /// Shown under Favorites.
    pub favorite: bool,
    /// ≤ 20 tags of 1..=50 characters.
    pub tags: Vec<String>,
    /// ≤ 64 KiB.
    pub notes: String,
    /// Client clock, informational.
    pub created_at: String,
    /// Client clock, informational.
    pub updated_at: String,
    /// Device that wrote this version (base64url device id).
    pub updated_by: String,
    /// ≤ 50 custom fields.
    pub custom_fields: Vec<CustomField>,
    /// Newest 10 previous passwords (logins).
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Set on conflict copies (sync.md §6.3).
    pub conflict_of: Option<String>,
    /// Keys this client does not understand, preserved verbatim.
    pub extra: Map<String, Value>,
}

/// Type-specific content.
#[derive(Clone, PartialEq)]
pub enum Content {
    /// A website or app login.
    Login(LoginFields),
    /// Free text in `notes`.
    Note(NoteFields),
    /// An SSH private key.
    SshKey(SshKeyFields),
    /// A type this client does not know; kept verbatim and read-only.
    Unknown {
        /// The `type` string.
        kind: String,
        /// The raw `fields` object.
        fields: Value,
    },
}

impl Content {
    /// The `type` string.
    pub fn kind(&self) -> &str {
        match self {
            Self::Login(_) => "login",
            Self::Note(_) => "note",
            Self::SshKey(_) => "ssh_key",
            Self::Unknown { kind, .. } => kind,
        }
    }
}

/// Login fields (data-model §1.2).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginFields {
    /// ≤ 500 characters.
    #[serde(default)]
    pub username: String,
    /// ≤ 1000 characters, concealed.
    #[serde(default)]
    pub password: String,
    /// ≤ 20 URLs.
    #[serde(default)]
    pub urls: Vec<LoginUrl>,
    /// Optional one-time password configuration.
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    /// Preserved unknown keys.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One URL on a login.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginUrl {
    /// The URL as entered.
    pub url: String,
    /// Label such as "website".
    #[serde(default)]
    pub label: String,
}

/// TOTP settings (RFC 6238).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32 (RFC 4648) secret, concealed.
    pub secret: String,
    /// `SHA1`, `SHA256` or `SHA512`.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// 6..=8.
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// 15..=120 seconds.
    #[serde(default = "default_period")]
    pub period: u32,
    /// Optional issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Optional account name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

fn default_algorithm() -> String {
    "SHA1".into()
}
fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}

/// Secure note fields (content lives in `notes`).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NoteFields {
    /// Preserved unknown keys.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// SSH key fields (data-model §1.4).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SshKeyFields {
    /// Unencrypted OpenSSH private key, concealed.
    pub private_key: String,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `ed25519`, `ecdsa-p256` or `rsa` (stored only).
    pub key_type: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    /// Key comment.
    #[serde(default)]
    pub comment: String,
    /// Agent settings.
    #[serde(default)]
    pub agent: SshAgentSettings,
    /// Preserved unknown keys.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether the SSH agent offers this key.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SshAgentSettings {
    /// Offered to SSH clients while unlocked.
    pub enabled: bool,
}

impl Default for SshAgentSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// A user-defined field (data-model §1.5).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomField {
    /// Random 8-byte id, base64url.
    pub id: String,
    /// Label.
    pub label: String,
    /// `text`, `concealed`, `url` or `email`.
    pub kind: String,
    /// Value.
    pub value: String,
}

/// A previous password (data-model §1.6).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    /// The old password, concealed.
    pub password: String,
    /// When it was replaced.
    pub replaced_at: String,
}

/// Wire shape used for (de)serialization.
#[derive(Serialize, Deserialize)]
struct RawItem {
    schema: u32,
    #[serde(rename = "type")]
    kind: String,
    title: String,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    updated_at: String,
    #[serde(default)]
    updated_by: String,
    #[serde(default)]
    fields: Value,
    #[serde(default)]
    custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    password_history: Vec<PasswordHistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conflict_of: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Item {
    /// A new item with empty common fields.
    pub fn new(content: Content, title: impl Into<String>, now: &str, device: &str) -> Self {
        Self {
            schema: SCHEMA,
            content,
            title: title.into(),
            favorite: false,
            tags: Vec::new(),
            notes: String::new(),
            created_at: now.into(),
            updated_at: now.into(),
            updated_by: device.into(),
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            conflict_of: None,
            extra: Map::new(),
        }
    }

    /// Whether this client may edit the item (known schema and type).
    pub fn is_editable(&self) -> bool {
        self.schema <= SCHEMA && !matches!(self.content, Content::Unknown { .. })
    }

    /// Parses a decrypted body. Validation errors are reported, never the content.
    pub fn from_json(body: &[u8]) -> Result<Self> {
        let raw: RawItem = serde_json::from_slice(body)
            .map_err(|_| VaultError::Invalid("item body is not valid"))?;
        let fields = if raw.fields.is_null() {
            Value::Object(Map::new())
        } else {
            raw.fields
        };
        let parse = |v: Value| -> Result<Content> {
            Ok(match raw.kind.as_str() {
                "login" => Content::Login(
                    serde_json::from_value(v).map_err(|_| VaultError::Invalid("login fields"))?,
                ),
                "note" => Content::Note(
                    serde_json::from_value(v).map_err(|_| VaultError::Invalid("note fields"))?,
                ),
                "ssh_key" => Content::SshKey(
                    serde_json::from_value(v).map_err(|_| VaultError::Invalid("ssh key fields"))?,
                ),
                other => Content::Unknown {
                    kind: other.to_owned(),
                    fields: v,
                },
            })
        };
        let content = if raw.schema > SCHEMA {
            // Newer schema: keep everything verbatim; the item is read-only.
            Content::Unknown {
                kind: raw.kind.clone(),
                fields,
            }
        } else {
            parse(fields)?
        };
        let item = Self {
            schema: raw.schema,
            content,
            title: raw.title,
            favorite: raw.favorite,
            tags: raw.tags,
            notes: raw.notes,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            updated_by: raw.updated_by,
            custom_fields: raw.custom_fields,
            password_history: raw.password_history,
            conflict_of: raw.conflict_of,
            extra: raw.extra,
        };
        Ok(item)
    }

    /// Serializes the body (after validation).
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let fields = match &self.content {
            Content::Login(f) => serde_json::to_value(f),
            Content::Note(f) => serde_json::to_value(f),
            Content::SshKey(f) => serde_json::to_value(f),
            Content::Unknown { fields, .. } => Ok(fields.clone()),
        }
        .map_err(|_| VaultError::Invalid("item fields"))?;
        let raw = RawItem {
            schema: self.schema,
            kind: self.content.kind().to_owned(),
            title: self.title.clone(),
            favorite: self.favorite,
            tags: self.tags.clone(),
            notes: self.notes.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            updated_by: self.updated_by.clone(),
            fields,
            custom_fields: self.custom_fields.clone(),
            password_history: self.password_history.clone(),
            conflict_of: self.conflict_of.clone(),
            extra: self.extra.clone(),
        };
        serde_json::to_vec(&raw).map_err(|_| VaultError::Invalid("item body"))
    }

    /// Checks the limits of data-model §1 and §5.
    pub fn validate(&self) -> Result<()> {
        let chars = |s: &str| s.chars().count();
        let check = |ok: bool, why: &'static str| {
            if ok {
                Ok(())
            } else {
                Err(VaultError::Invalid(why))
            }
        };
        check(
            (1..=200).contains(&chars(self.title.trim())),
            "title must be 1–200 characters",
        )?;
        check(self.tags.len() <= 20, "at most 20 tags")?;
        check(
            self.tags.iter().all(|t| (1..=50).contains(&chars(t))),
            "tags must be 1–50 characters",
        )?;
        check(self.notes.len() <= 64 * 1024, "notes are limited to 64 KiB")?;
        check(self.custom_fields.len() <= 50, "at most 50 custom fields")?;
        check(
            self.custom_fields
                .iter()
                .all(|f| matches!(f.kind.as_str(), "text" | "concealed" | "url" | "email")),
            "unknown custom field kind",
        )?;
        check(
            self.password_history.len() <= 10,
            "at most 10 history entries",
        )?;
        match &self.content {
            Content::Login(l) => {
                check(
                    chars(&l.username) <= 500,
                    "username is limited to 500 characters",
                )?;
                check(
                    chars(&l.password) <= 1000,
                    "password is limited to 1000 characters",
                )?;
                check(l.urls.len() <= 20, "at most 20 URLs")?;
                if let Some(t) = &l.totp {
                    crate::totp::Totp::from_config(t)?;
                }
            }
            Content::Note(_) => {}
            Content::SshKey(k) => {
                check(
                    !k.private_key.is_empty() && !k.public_key.is_empty(),
                    "SSH key is incomplete",
                )?;
            }
            Content::Unknown { .. } => {}
        }
        Ok(())
    }

    /// Records the previous password in history when a login's password changes (data-model §1.6).
    pub fn record_password_change(&mut self, previous: &Item, now: &str) {
        if let (Content::Login(old), Content::Login(new)) = (&previous.content, &self.content)
            && !old.password.is_empty()
            && old.password != new.password
        {
            self.password_history.insert(
                0,
                PasswordHistoryEntry {
                    password: old.password.clone(),
                    replaced_at: now.to_owned(),
                },
            );
            self.password_history.truncate(10);
        }
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        // Best effort: wipe the obvious secret strings.
        self.notes.zeroize();
        match &mut self.content {
            Content::Login(l) => {
                l.password.zeroize();
                if let Some(t) = &mut l.totp {
                    t.secret.zeroize();
                }
            }
            Content::SshKey(k) => k.private_key.zeroize(),
            _ => {}
        }
        for h in &mut self.password_history {
            h.password.zeroize();
        }
        for f in &mut self.custom_fields {
            f.value.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Item {
        let mut i = Item::new(
            Content::Login(LoginFields {
                username: "alice".into(),
                password: "hunter2".into(),
                urls: vec![LoginUrl {
                    url: "https://example.com".into(),
                    label: "website".into(),
                }],
                ..Default::default()
            }),
            "Example",
            "2026-11-26T10:00:00Z",
            "dev",
        );
        i.tags = vec!["work".into()];
        i
    }

    #[test]
    fn round_trip() {
        let item = login();
        let parsed = Item::from_json(&item.to_json().unwrap()).unwrap();
        assert!(parsed == item);
    }

    #[test]
    fn unknown_keys_are_preserved() {
        let body = br#"{"schema":1,"type":"login","title":"T","future":{"x":1},
            "fields":{"username":"u","password":"p","urls":[],"passkey":"abc"}}"#;
        let item = Item::from_json(body).unwrap();
        let out: Value = serde_json::from_slice(&item.to_json().unwrap()).unwrap();
        assert_eq!(out["future"]["x"], 1);
        assert_eq!(out["fields"]["passkey"], "abc");
    }

    #[test]
    fn newer_schema_and_unknown_type_are_read_only_and_preserved() {
        let newer = br#"{"schema":9,"type":"login","title":"T","fields":{"username":5}}"#;
        let item = Item::from_json(newer).unwrap();
        assert!(!item.is_editable());
        let out: Value = serde_json::from_slice(&item.to_json().unwrap()).unwrap();
        assert_eq!(out["fields"]["username"], 5);
        let unknown = br#"{"schema":1,"type":"passport","title":"P","fields":{"n":"1"}}"#;
        let item = Item::from_json(unknown).unwrap();
        assert_eq!(item.content.kind(), "passport");
        assert!(!item.is_editable());
    }

    #[test]
    fn validation_limits() {
        let mut i = login();
        i.title = " ".into();
        assert!(i.validate().is_err());
        let mut i = login();
        i.tags = vec!["x".into(); 21];
        assert!(i.validate().is_err());
        let mut i = login();
        if let Content::Login(l) = &mut i.content {
            l.password = "p".repeat(1001);
        }
        assert!(i.validate().is_err());
        let mut i = login();
        i.custom_fields.push(CustomField {
            id: "a".into(),
            label: "l".into(),
            kind: "weird".into(),
            value: "v".into(),
        });
        assert!(i.validate().is_err());
    }

    #[test]
    fn password_history_records_changes() {
        let old = login();
        let mut new = login();
        if let Content::Login(l) = &mut new.content {
            l.password = "new".into();
        }
        new.record_password_change(&old, "now");
        assert_eq!(new.password_history.len(), 1);
        assert_eq!(new.password_history[0].password, "hunter2");
    }

    #[test]
    fn invalid_json_errors_do_not_echo_content() {
        let err = Item::from_json(
            b"{\"schema\":1,\"type\":\"login\",\"title\":\"SECRET\",\"fields\":{\"password\":7}}",
        )
        .err()
        .unwrap();
        assert!(!err.to_string().contains("SECRET"));
    }
}
