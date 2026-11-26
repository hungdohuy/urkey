//! Human-readable encodings of the Account Secret Key and Recovery Key (spec §3.2).
//!
//! Crockford base32 (MSB-first bit packing, final symbol zero-padded on the right), followed by
//! one Crockford mod-37 check symbol over the payload bytes read as a big-endian integer. Input is
//! case-insensitive, `I`/`L` read as `1`, `O` as `0`, and hyphens and whitespace are ignored. The
//! check symbol only catches typos; it is not a security mechanism.
//!
//! Display grouping: the payload is split into groups and the check symbol is appended to the
//! last group. Grouping is cosmetic; the parser ignores separators.

use zeroize::{Zeroize, Zeroizing};

use crate::secret::{AccountSecretKey, RecoveryKey};
use crate::{CryptoError, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Check symbols for values 32..=36 (Crockford).
const CHECK_EXTRA: &[u8; 5] = b"*~$=U";

const ASK_PREFIX: &str = "UK1";
const ASK_GROUPS: &[usize] = &[6, 5, 5, 5, 5];
const RK_PREFIX: &str = "UKR1";
const RK_GROUPS: &[usize] = &[4; 13];

/// Formats an Account Secret Key, e.g. `UK1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXC`.
pub fn format_account_secret_key(key: &AccountSecretKey) -> Zeroizing<String> {
    format_key(ASK_PREFIX, ASK_GROUPS, key.expose_secret())
}

/// Parses an Account Secret Key typed or pasted by the user.
pub fn parse_account_secret_key(input: &str) -> Result<AccountSecretKey> {
    let bytes = parse_key(ASK_PREFIX, 16, input, "not a valid Secret Key")?;
    AccountSecretKey::from_slice(&bytes)
}

/// Formats a Recovery Key, e.g. `UKR1-XXXX-…-XXXXC`.
pub fn format_recovery_key(key: &RecoveryKey) -> Zeroizing<String> {
    format_key(RK_PREFIX, RK_GROUPS, key.expose_secret())
}

/// Parses a Recovery Key typed or pasted by the user.
pub fn parse_recovery_key(input: &str) -> Result<RecoveryKey> {
    let bytes = parse_key(RK_PREFIX, 32, input, "not a valid Recovery Key")?;
    RecoveryKey::from_slice(&bytes)
}

fn format_key(prefix: &str, groups: &[usize], bytes: &[u8]) -> Zeroizing<String> {
    let payload = encode_base32(bytes);
    let mut out = Zeroizing::new(String::with_capacity(
        prefix.len() + payload.len() + groups.len() + 2,
    ));
    out.push_str(prefix);
    let mut pos = 0;
    for len in groups {
        out.push('-');
        out.push_str(payload.get(pos..pos + len).unwrap_or_default());
        pos += len;
    }
    out.push(char::from(check_symbol(bytes)));
    out
}

fn parse_key(
    prefix: &str,
    byte_len: usize,
    input: &str,
    reason: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut compact = Zeroizing::new(String::with_capacity(input.len()));
    compact.extend(
        input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| match c.to_ascii_uppercase() {
                // Crockford look-alikes, applied everywhere including the prefix.
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            }),
    );
    let rest = compact
        .strip_prefix(prefix)
        .ok_or(CryptoError::InvalidInput(reason))?;
    let symbols = base32_len(byte_len);
    if rest.len() != symbols + 1 || !rest.is_ascii() {
        return Err(CryptoError::InvalidInput(reason));
    }
    let (payload, check) = rest.split_at(symbols);
    let bytes = decode_base32(payload, byte_len).ok_or(CryptoError::InvalidInput(reason))?;
    let expected = check_symbol(&bytes);
    let given = check.as_bytes().first().copied();
    if given != Some(expected) {
        return Err(CryptoError::InvalidInput(reason));
    }
    Ok(bytes)
}

const fn base32_len(byte_len: usize) -> usize {
    (byte_len * 8).div_ceil(5)
}

fn encode_base32(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(base32_len(bytes.len())));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    acc.zeroize();
    out
}

/// Decodes exactly `byte_len` bytes; rejects non-canonical input (non-zero padding bits).
fn decode_base32(symbols: &str, byte_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(byte_len));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in symbols.bytes() {
        let value = symbol_value(c)?;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    let canonical = acc == 0 && out.len() == byte_len;
    acc.zeroize();
    canonical.then_some(out)
}

fn symbol_value(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u32::try_from(p).ok())
}

/// Crockford check symbol: the payload as a big-endian integer, modulo 37.
fn check_symbol(bytes: &[u8]) -> u8 {
    let rem = bytes
        .iter()
        .fold(0u32, |r, &b| (r * 256 + u32::from(b)) % 37);
    let idx = rem as usize;
    ALPHABET
        .get(idx)
        .or_else(|| CHECK_EXTRA.get(idx - 32))
        .copied()
        .unwrap_or(b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(bytes: [u8; 16]) -> AccountSecretKey {
        AccountSecretKey::from_slice(&bytes).unwrap()
    }

    #[test]
    fn known_base32_values() {
        // RFC 4648-style bit packing with the Crockford alphabet.
        assert_eq!(encode_base32(&[0x00]).as_str(), "00");
        assert_eq!(encode_base32(&[0xFF]).as_str(), "ZW");
        assert_eq!(
            encode_base32(&[0x01, 0x02, 0x03, 0x04, 0x05]).as_str(),
            "04106105"
        );
    }

    #[test]
    fn check_symbol_matches_crockford_definition() {
        assert_eq!(check_symbol(&[0]), b'0');
        assert_eq!(check_symbol(&[36]), b'U');
        assert_eq!(check_symbol(&[32]), b'*');
        // 256 mod 37 = 34 -> '$'
        assert_eq!(check_symbol(&[1, 0]), b'$');
    }

    #[test]
    fn ask_round_trip_and_shape() {
        let key = ask([0x5A; 16]);
        let text = format_account_secret_key(&key);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups[0], "UK1");
        assert_eq!(
            groups[1..].iter().map(|g| g.len()).collect::<Vec<_>>(),
            [6, 5, 5, 5, 6]
        );
        let parsed = parse_account_secret_key(&text).unwrap();
        assert_eq!(parsed.expose_secret(), key.expose_secret());
    }

    #[test]
    fn rk_round_trip_and_shape() {
        let key = RecoveryKey::from_slice(&[0xC3; 32]).unwrap();
        let text = format_recovery_key(&key);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups[0], "UKR1");
        assert_eq!(groups.len(), 14);
        assert!(groups[1..13].iter().all(|g| g.len() == 4));
        assert_eq!(groups[13].len(), 5);
        assert_eq!(
            parse_recovery_key(&text).unwrap().expose_secret(),
            key.expose_secret()
        );
    }

    #[test]
    fn parsing_is_forgiving_about_case_separators_and_lookalikes() {
        let key = ask([0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let text = format_account_secret_key(&key)
            .to_ascii_lowercase()
            .replace('-', " ");
        let typed = text.replace('0', "o").replace('1', "l");
        assert_eq!(
            parse_account_secret_key(&typed).unwrap().expose_secret(),
            key.expose_secret()
        );
    }

    #[test]
    fn typos_and_wrong_types_are_rejected() {
        let key = ask([7; 16]);
        let text = format_account_secret_key(&key).to_string();
        // Change one payload symbol.
        let mut chars: Vec<char> = text.chars().collect();
        chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(parse_account_secret_key(&typo).is_err());
        // Wrong prefix / wrong key type / truncated / extra.
        assert!(parse_recovery_key(&text).is_err());
        assert!(parse_account_secret_key(&text[..text.len() - 1]).is_err());
        assert!(parse_account_secret_key(&format!("{text}0")).is_err());
        assert!(parse_account_secret_key("").is_err());
        // 'U' is a check-only symbol and invalid in the payload.
        assert!(parse_account_secret_key("UK1-UUUUUU-UUUUU-UUUUU-UUUUU-UUUUU0").is_err());
    }

    #[test]
    fn non_canonical_padding_bits_are_rejected() {
        // 16 bytes = 128 bits in 26 symbols (130 bits): the last 2 bits must be zero.
        let key = ask([0; 16]);
        let text = format_account_secret_key(&key).to_string();
        let payload_end = text.len() - 1;
        let mut bad = text.clone();
        bad.replace_range(payload_end - 1..payload_end, "1");
        assert!(parse_account_secret_key(&bad).is_err());
    }

    #[test]
    fn errors_do_not_echo_input() {
        let err = parse_account_secret_key("UK1-SECRETSECRET").unwrap_err();
        assert!(!err.to_string().contains("SECRET"));
    }
}
