//! Clipboard copy with automatic clearing (R-ITEM-7, design-principles "Copy").
//!
//! The value goes to the platform clipboard tool through its stdin: `pbcopy` on macOS, and
//! `wl-copy` (Wayland) or `xclip` (X11) on Linux. A detached helper (`urk __clear-clipboard`)
//! receives the value on **stdin**, never as an argument, because arguments are visible in `ps`.
//! It waits, then clears the clipboard only if it still holds that value, so it never wipes
//! something the user copied afterwards.
//!
//! Development and tests: `URKEY_CLIPBOARD_COPY` / `URKEY_CLIPBOARD_PASTE` name programs to
//! use instead (stdin = value / stdout = current value), and `URKEY_CLIPBOARD_CLEAR_SECS`
//! shortens the 90 s delay.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{CliError, Result};

/// R-ITEM-7: clear after 90 seconds.
pub const CLEAR_AFTER_SECS: u64 = 90;

struct Tools {
    copy: Vec<String>,
    paste: Vec<String>,
}

fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

fn tools() -> Result<Tools> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if let (Some(c), Some(p)) = (env("URKEY_CLIPBOARD_COPY"), env("URKEY_CLIPBOARD_PASTE")) {
        return Ok(Tools {
            copy: vec![c],
            paste: vec![p],
        });
    }
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    if cfg!(target_os = "macos") {
        return Ok(Tools {
            copy: v(&["pbcopy"]),
            paste: v(&["pbpaste"]),
        });
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && on_path("wl-copy") && on_path("wl-paste") {
        return Ok(Tools {
            copy: v(&["wl-copy"]),
            paste: v(&["wl-paste", "--no-newline"]),
        });
    }
    if on_path("xclip") {
        return Ok(Tools {
            copy: v(&["xclip", "-selection", "clipboard"]),
            paste: v(&["xclip", "-selection", "clipboard", "-o"]),
        });
    }
    Err(CliError::new(
        "no clipboard tool found (pbcopy, wl-copy or xclip); use `urk item get --field` instead",
    ))
}

fn write_clipboard(t: &Tools, value: &[u8]) -> Result<()> {
    let mut child = Command::new(&t.copy[0])
        .args(&t.copy[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CliError::new("could not start the clipboard tool"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(value)
            .map_err(|_| CliError::new("could not write to the clipboard"))?;
    }
    let ok = child.wait().is_ok_and(|s| s.success());
    if ok {
        Ok(())
    } else {
        Err(CliError::new("the clipboard tool failed"))
    }
}

fn read_clipboard(t: &Tools) -> Option<Zeroizing<Vec<u8>>> {
    let out = Command::new(&t.paste[0])
        .args(&t.paste[1..])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| Zeroizing::new(out.stdout))
}

fn clear_delay() -> u64 {
    std::env::var("URKEY_CLIPBOARD_CLEAR_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| (1..=CLEAR_AFTER_SECS).contains(s))
        .unwrap_or(CLEAR_AFTER_SECS)
}

/// Copies `value` and schedules clearing. Returns the delay in seconds.
pub fn copy_and_schedule_clear(value: &str) -> Result<u64> {
    let t = tools()?;
    write_clipboard(&t, value.as_bytes())?;
    let delay = clear_delay();
    let exe = std::env::current_exe().map_err(|_| CliError::new("could not schedule clearing"))?;
    // Own process group: Ctrl-C or closing the terminal does not stop the clearing.
    let mut child = Command::new(exe)
        .arg("__clear-clipboard")
        .arg(delay.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| CliError::new("could not schedule clearing"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(value.as_bytes())
            .map_err(|_| CliError::new("could not schedule clearing"))?;
    }
    Ok(delay)
}

/// The detached helper: reads the copied value from stdin, waits, and clears the clipboard if
/// it still holds that value.
pub fn clear_after(delay_secs: u64) -> Result<()> {
    let mut expected = Zeroizing::new(Vec::new());
    std::io::stdin()
        .read_to_end(&mut expected)
        .map_err(|_| CliError::new("could not read"))?;
    std::thread::sleep(Duration::from_secs(delay_secs.min(CLEAR_AFTER_SECS)));
    let t = tools()?;
    if read_clipboard(&t).is_some_and(|now| *now == *expected) {
        write_clipboard(&t, b"")?;
    }
    Ok(())
}
