//! Opt-in timing of the default unlock derivation (spec §4.2 calibration).
//!
//! `cargo test -p crypto-core --release --test bench_argon2 -- --ignored --nocapture`
//! The WASM figure comes from `tests/wasm.rs`.
#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::time::Instant;

use crypto_core::ids::{AccountId, KdfSalt};
use crypto_core::kdf::{KdfParams, derive_unlock};
use crypto_core::secret::AccountSecretKey;

#[test]
#[ignore = "benchmark; run explicitly"]
fn default_unlock_derivation_time() {
    let ask = AccountSecretKey::from_slice(&[1; 16]).unwrap();
    let (id, salt) = (AccountId::from_bytes([2; 16]), KdfSalt::from_bytes([3; 16]));
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        derive_unlock("benchmark password", &ask, &id, &salt, &KdfParams::DEFAULT).unwrap();
        best = best.min(start.elapsed().as_secs_f64() * 1000.0);
    }
    eprintln!("BENCH argon2id m=64MiB t=3 p=1 (native): best of 5 = {best:.0} ms");
}
