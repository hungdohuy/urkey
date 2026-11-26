//! Item payload padding (spec §5.4):
//! `plaintext = u32be(len(body)) ‖ body ‖ zero padding`, total length = next power of two
//! ≥ 512 bytes up to 64 KiB, then the next multiple of 64 KiB. Body ≤ 1 MiB.

use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Largest accepted body.
pub const MAX_BODY_LEN: usize = 1 << 20;
const MIN_PADDED: usize = 512;
const BUCKET: usize = 64 * 1024;

/// Padded plaintext length for a body of `body_len` bytes.
pub fn padded_len(body_len: usize) -> Result<usize> {
    if body_len > MAX_BODY_LEN {
        return Err(CryptoError::InvalidInput("item is too large"));
    }
    let total = body_len + 4;
    Ok(if total <= MIN_PADDED {
        MIN_PADDED
    } else if total <= BUCKET {
        total.next_power_of_two()
    } else {
        total.div_ceil(BUCKET) * BUCKET
    })
}

/// Pads a body for encryption.
pub fn pad(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let total = padded_len(body.len())?;
    let len =
        u32::try_from(body.len()).map_err(|_| CryptoError::InvalidInput("item is too large"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(total, 0);
    Ok(out)
}

/// Removes padding after decryption. Any inconsistency is a [`CryptoError::Decrypt`].
pub fn unpad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (len_bytes, rest) = plaintext
        .split_first_chunk::<4>()
        .ok_or(CryptoError::Decrypt)?;
    let len = usize::try_from(u32::from_be_bytes(*len_bytes)).map_err(|_| CryptoError::Decrypt)?;
    let expected_total = padded_len(len).map_err(|_| CryptoError::Decrypt)?;
    if plaintext.len() != expected_total {
        return Err(CryptoError::Decrypt);
    }
    let (body, padding) = rest.split_at_checked(len).ok_or(CryptoError::Decrypt)?;
    // Non-secret structure check: padding bytes must all be zero.
    if padding.iter().any(|&b| b != 0) {
        return Err(CryptoError::Decrypt);
    }
    Ok(Zeroizing::new(body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries() {
        assert_eq!(padded_len(0).unwrap(), 512);
        assert_eq!(padded_len(508).unwrap(), 512);
        assert_eq!(padded_len(509).unwrap(), 1024);
        assert_eq!(padded_len(65_532).unwrap(), 65_536);
        assert_eq!(padded_len(65_533).unwrap(), 131_072);
        assert_eq!(padded_len(131_068).unwrap(), 131_072);
        assert_eq!(padded_len(131_069).unwrap(), 196_608);
        assert_eq!(padded_len(MAX_BODY_LEN).unwrap(), MAX_BODY_LEN + BUCKET);
        assert!(padded_len(MAX_BODY_LEN + 1).is_err());
    }

    #[test]
    fn round_trip() {
        for len in [0, 1, 508, 509, 4096, 70_000] {
            let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad(&body).unwrap();
            assert_eq!(padded.len(), padded_len(len).unwrap());
            assert_eq!(unpad(&padded).unwrap().as_slice(), body.as_slice());
        }
    }

    #[test]
    fn malformed_padding_is_rejected() {
        let mut padded = pad(b"hello").unwrap();
        let last = padded.len() - 1;
        padded[last] = 1;
        assert_eq!(unpad(&padded).unwrap_err(), CryptoError::Decrypt);
        // A length that implies a different bucket than the buffer size.
        let mut wrong_len = pad(b"hello").unwrap();
        wrong_len[2] = 0x02; // 0x0205 = 517 bytes -> 1024-byte bucket, buffer is 512
        assert_eq!(unpad(&wrong_len).unwrap_err(), CryptoError::Decrypt);
        assert_eq!(
            unpad(&pad(b"hello").unwrap()[..100]).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(unpad(&[0, 0]).unwrap_err(), CryptoError::Decrypt);
    }
}
