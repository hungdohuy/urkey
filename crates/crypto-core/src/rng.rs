//! Randomness (spec §9): only the operating system CSPRNG, failing closed.

use crate::{CryptoError, Result};

pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

pub(crate) fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
