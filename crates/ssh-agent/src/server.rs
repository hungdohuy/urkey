//! Unix-socket server (threat model T-18): socket in a 0700 directory, mode 0600, and every
//! connection's peer uid must equal ours.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::Agent;
use crate::protocol::{read_frame, write_frame};

/// Default socket path: `<data dir>/agent.sock`.
pub fn default_socket(data_dir: &Path) -> PathBuf {
    data_dir.join("agent.sock")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials)
        .map(|c| c.uid())
        .map_err(io::Error::from)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    nix::unistd::getpeereid(stream)
        .map(|(uid, _)| uid.as_raw())
        .map_err(io::Error::from)
}

fn serve_connection(agent: &Agent, mut stream: UnixStream) {
    let ours = nix::unistd::getuid().as_raw();
    if peer_uid(&stream).ok() != Some(ours) {
        return; // another user: close without answering
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
    while let Ok(req) = read_frame(&mut stream) {
        let resp = agent.handle(&req);
        if write_frame(&mut stream, &resp).is_err() {
            break;
        }
    }
}

/// Prepares the socket path: parent directory 0700, stale socket removed.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        // Refuse to replace a live agent; remove only a stale socket.
        if UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "an agent is already running",
            ));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves until `stop` is set. Expired keys are purged every few seconds even when idle.
pub fn serve(listener: UnixListener, agent: Arc<Agent>, stop: Arc<AtomicBool>) -> io::Result<()> {
    {
        let agent = Arc::clone(&agent);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                agent.purge_expired();
                thread::sleep(Duration::from_secs(2));
            }
        });
    }
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let agent = Arc::clone(&agent);
                thread::spawn(move || serve_connection(&agent, stream));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Sends one request to an agent socket and returns the response payload.
pub fn request(path: &Path, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(path)?;
    write_frame(&mut s, payload).map_err(|e| io::Error::other(e.to_string()))?;
    read_frame(&mut s).map_err(|e| io::Error::other(e.to_string()))
}
