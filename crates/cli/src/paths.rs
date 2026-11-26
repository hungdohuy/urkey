//! Data directory (data-model §4.2): `~/Library/Application Support/urkey` on macOS,
//! `$XDG_DATA_HOME/urkey` or `~/.local/share/urkey` elsewhere; `URKEY_HOME` overrides.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::error::{CliError, Result};

pub fn data_dir() -> Result<PathBuf> {
    let dir = if let Some(custom) = std::env::var_os("URKEY_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(custom)
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| CliError::new("HOME is not set"))?;
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/urkey")
        } else if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("urkey")
        } else {
            home.join(".local/share/urkey")
        }
    };
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
