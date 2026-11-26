//! Interoperability with real OpenSSH tools (`ssh-add`, `ssh-keygen -Y sign`). Skipped when
//! OpenSSH is not installed. Keys are generated per run (test-only).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use ssh_agent::{Agent, server};

fn have(tool: &str) -> bool {
    Command::new(tool).arg("-V").output().is_ok()
        || Command::new("which")
            .arg(tool)
            .output()
            .is_ok_and(|o| o.status.success())
}

struct Fixture {
    dir: PathBuf,
    sock: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "urkey-agent-test-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    let sock = server::default_socket(&dir.join("run"));
    let listener = server::bind(&sock).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (agent, s) = (Arc::new(Agent::new()), Arc::clone(&stop));
    thread::spawn(move || server::serve(listener, agent, s).unwrap());
    Fixture { dir, sock, stop }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn keygen(dir: &Path, name: &str, args: &[&str]) -> PathBuf {
    let path = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-C", &format!("test-only-{name}"), "-f"])
        .arg(&path)
        .args(args)
        .status()
        .unwrap();
    assert!(ok.success());
    path
}

fn run(f: &Fixture, cmd: &str, args: &[&str]) -> Output {
    Command::new(cmd)
        .args(args)
        .env("SSH_AUTH_SOCK", &f.sock)
        .output()
        .unwrap()
}

#[test]
fn openssh_tools_work_against_the_agent() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH not installed; skipping");
        return;
    }
    let f = start();
    let ed = keygen(&f.dir, "ed25519", &["-t", "ed25519"]);
    let ec = keygen(&f.dir, "ecdsa", &["-t", "ecdsa", "-b", "256"]);
    let rsa = keygen(&f.dir, "rsa", &["-t", "rsa", "-b", "2048"]);

    assert!(
        run(
            &f,
            "ssh-add",
            &["-t", "600", ed.to_str().unwrap(), ec.to_str().unwrap()]
        )
        .status
        .success()
    );
    let list = String::from_utf8(run(&f, "ssh-add", &["-l"]).stdout).unwrap();
    assert!(list.contains("test-only-ed25519 (ED25519)"), "{list}");
    assert!(list.contains("test-only-ecdsa (ECDSA)"), "{list}");

    // Sign through the agent and verify with OpenSSH, for both key types.
    let data = f.dir.join("data.txt");
    std::fs::write(&data, b"urkey agent interop test").unwrap();
    for key in [&ed, &ec] {
        let pubkey = format!("{}.pub", key.display());
        let out = run(
            &f,
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-n",
                "test",
                "-f",
                &pubkey,
                data.to_str().unwrap(),
            ],
        );
        assert!(
            out.status.success(),
            "sign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let sig = format!("{}.sig", data.display());
        let check = Command::new("ssh-keygen")
            .args([
                "-Y",
                "check-novalidate",
                "-n",
                "test",
                "-f",
                &pubkey,
                "-s",
                &sig,
            ])
            .stdin(std::fs::File::open(&data).unwrap())
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "verify failed: {}",
            String::from_utf8_lossy(&check.stderr)
        );
        std::fs::remove_file(&sig).unwrap();
    }

    // RSA and confirm-on-use are refused (ADR 0008, R-SSH-5 deferred).
    assert!(
        !run(&f, "ssh-add", &[rsa.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        !run(&f, "ssh-add", &["-c", ed.to_str().unwrap()])
            .status
            .success()
    );

    // Remove all.
    assert!(run(&f, "ssh-add", &["-D"]).status.success());
    assert!(!run(&f, "ssh-add", &["-l"]).status.success()); // "The agent has no identities."
}

#[test]
fn lifetimes_expire() {
    if !have("ssh-add") || !have("ssh-keygen") {
        return;
    }
    let f = start();
    let ed = keygen(&f.dir, "ed25519", &["-t", "ed25519"]);
    assert!(
        run(&f, "ssh-add", &["-t", "1", ed.to_str().unwrap()])
            .status
            .success()
    );
    assert!(run(&f, "ssh-add", &["-l"]).status.success());
    thread::sleep(Duration::from_millis(2500));
    assert!(!run(&f, "ssh-add", &["-l"]).status.success());
}

#[test]
fn socket_is_private_and_a_second_agent_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let f = start();
    let mode = std::fs::metadata(&f.sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(f.sock.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert!(server::bind(&f.sock).is_err());
}
