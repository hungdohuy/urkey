//! `urkey` command-line interface (requirements R-SSH-4).
//!
//! Only `--version` and `--help` exist until roadmap P6.

use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "urkey — personal password manager CLI\n\nUSAGE:\n    urkey [--version | --help]\n\nVault and SSH agent commands arrive in a later phase.\n";

fn run(args: &[String], out: &mut impl Write) -> io::Result<ExitCode> {
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            writeln!(out, "urkey {}", env!("CARGO_PKG_VERSION"))?;
            Ok(ExitCode::SUCCESS)
        }
        None | Some("--help" | "-h") => {
            out.write_all(USAGE.as_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
        Some(_) => {
            out.write_all(USAGE.as_bytes())?;
            Ok(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args, &mut io::stdout().lock()).unwrap_or(ExitCode::FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(args: &[&str]) -> (ExitCode, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let mut buf = Vec::new();
        let code = run(&args, &mut buf).unwrap();
        (code, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn prints_version() {
        let (code, out) = output(&["--version"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(out, format!("urkey {}\n", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn unknown_argument_prints_usage_and_fails() {
        let (code, out) = output(&["frobnicate"]);
        assert_eq!(code, ExitCode::from(2));
        assert!(out.starts_with("urkey —"));
    }
}
