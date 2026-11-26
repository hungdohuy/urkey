//! Terminal output helpers (the workspace forbids print macros; secrets are never logged).

use std::io::Write;

pub fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
}

pub fn err(line: &str) {
    let mut out = std::io::stderr().lock();
    let _ = writeln!(out, "{line}");
}

/// launchd agent definition for `urk agent run` (macOS).
pub fn launchd_plist(exe: &str, data_dir: &str) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.urkey.agent</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>agent</string><string>run</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>URKEY_HOME</key><string>{}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#,
        esc(exe),
        esc(data_dir)
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_escapes_paths() {
        let p = super::launchd_plist("/a&b/urk", "/x<y>");
        assert!(p.contains("/a&amp;b/urk"));
        assert!(p.contains("/x&lt;y&gt;"));
    }
}
