//! OS CSPRNG only (crypto design §9).

use crate::{Result, VaultError};

pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| VaultError::Rng)
}

/// Uniform integer in `0..bound` by rejection sampling (no modulo bias).
pub(crate) fn below(bound: u32) -> Result<u32> {
    debug_assert!(bound > 0);
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut b = [0u8; 4];
        fill(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % bound);
        }
    }
}
