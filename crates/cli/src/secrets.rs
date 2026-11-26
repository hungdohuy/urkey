//! Secret storage for the Account Secret Key and the device key seed (D-5, ADR 0006).
//!
//! - macOS: Keychain generic passwords (service `dev.urkey`), one entry per data directory.
//! - Other platforms (development only): `secrets.json` (mode 0600) in the data directory.

use crate::vault_core;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{CliError, Result};

pub trait SecretStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn set(&self, name: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
}

pub fn open(dir: &Path) -> Box<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(keychain::Keychain {
            scope: dir.display().to_string(),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(FileStore {
            path: dir.join("secrets.json"),
        })
    }
}

#[cfg(target_os = "macos")]
mod keychain {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use zeroize::Zeroizing;

    use super::SecretStore;
    use crate::error::{CliError, Result};

    const SERVICE: &str = "dev.urkey";

    pub struct Keychain {
        pub scope: String,
    }

    impl Keychain {
        fn account(&self, name: &str) -> String {
            format!("{}:{name}", self.scope)
        }
    }

    impl SecretStore for Keychain {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            match get_generic_password(SERVICE, &self.account(name)) {
                Ok(v) => Ok(Some(Zeroizing::new(v))),
                Err(e) if e.code() == -25300 => Ok(None), // errSecItemNotFound
                Err(_) => Err(CliError::new("Keychain access failed")),
            }
        }
        fn set(&self, name: &str, value: &[u8]) -> Result<()> {
            set_generic_password(SERVICE, &self.account(name), value)
                .map_err(|_| CliError::new("Keychain access failed"))
        }
        fn delete(&self, name: &str) -> Result<()> {
            match delete_generic_password(SERVICE, &self.account(name)) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == -25300 => Ok(()),
                Err(_) => Err(CliError::new("Keychain access failed")),
            }
        }
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    fn load(&self) -> Result<Zeroizing<String>> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Zeroizing::new("{}".into())),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, map: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        let text = Zeroizing::new(serde_json::to_string(map)?);
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

impl SecretStore for FileStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let raw = self.load()?;
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)?;
        match map.get(name).and_then(|v| v.as_str()) {
            Some(s) => Ok(Some(Zeroizing::new(
                vault_core::b64::decode(s).map_err(|_| CliError::new("secret store is damaged"))?,
            ))),
            None => Ok(None),
        }
    }
    fn set(&self, name: &str, value: &[u8]) -> Result<()> {
        let raw = self.load()?;
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)?;
        map.insert(name.to_owned(), vault_core::b64::encode(value).into());
        self.save(&map)
    }
    fn delete(&self, name: &str) -> Result<()> {
        let raw = self.load()?;
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)?;
        map.remove(name);
        self.save(&map)
    }
}
