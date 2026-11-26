//! RFC 6238 TOTP over RFC 4226 HOTP (crypto design §11.1), and `otpauth://totp/` URI parsing.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::item::TotpConfig;
use crate::{Result, VaultError};

/// HMAC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA-1 (the common default).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// A validated TOTP generator. The secret is wiped on drop and never printed.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u32,
}

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .finish_non_exhaustive()
    }
}

/// A generated code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// Zero-padded digits.
    pub code: String,
    /// Seconds until the code changes.
    pub seconds_remaining: u32,
    /// Step length in seconds.
    pub period: u32,
}

impl Totp {
    /// Validates an item's TOTP configuration (data-model §1.2).
    pub fn from_config(config: &TotpConfig) -> Result<Self> {
        let algorithm = match config.algorithm.to_ascii_uppercase().as_str() {
            "SHA1" => Algorithm::Sha1,
            "SHA256" => Algorithm::Sha256,
            "SHA512" => Algorithm::Sha512,
            _ => {
                return Err(VaultError::Invalid(
                    "unsupported one-time password algorithm",
                ));
            }
        };
        if !(6..=8).contains(&config.digits) {
            return Err(VaultError::Invalid("one-time passwords have 6–8 digits"));
        }
        if !(15..=120).contains(&config.period) {
            return Err(VaultError::Invalid(
                "one-time password period must be 15–120 seconds",
            ));
        }
        let secret = decode_base32(&config.secret).ok_or(VaultError::Invalid(
            "one-time password secret is not valid base32",
        ))?;
        if secret.is_empty() {
            return Err(VaultError::Invalid("one-time password secret is empty"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits: config.digits,
            period: config.period,
        })
    }

    /// The code for Unix time `unix_seconds`.
    pub fn code_at(&self, unix_seconds: u64) -> Code {
        let counter = unix_seconds / u64::from(self.period);
        let remaining = self.period - (unix_seconds % u64::from(self.period)) as u32;
        let value = hotp(&self.secret, counter, self.algorithm) % 10u32.pow(self.digits);
        Code {
            code: format!("{value:0width$}", width = self.digits as usize),
            seconds_remaining: remaining,
            period: self.period,
        }
    }
}

/// RFC 4226 §5.3 dynamic truncation, returning the 31-bit value.
fn hotp(secret: &[u8], counter: u64, algorithm: Algorithm) -> u32 {
    let msg = counter.to_be_bytes();
    let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match algorithm {
        Algorithm::Sha1 => mac::<Hmac<Sha1>>(secret, &msg),
        Algorithm::Sha256 => mac::<Hmac<Sha256>>(secret, &msg),
        Algorithm::Sha512 => mac::<Hmac<Sha512>>(secret, &msg),
    });
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
}

fn mac<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so this cannot fail.
    match <M as KeyInit>::new_from_slice(key) {
        Ok(mut m) => {
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

/// RFC 4648 base32, case-insensitive, ignoring spaces, hyphens and `=` padding.
pub fn decode_base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(Vec::new());
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|c| !matches!(c, b' ' | b'-' | b'=')) {
        let v = ALPHABET.iter().position(|&a| a == c.to_ascii_uppercase())? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    Some(out)
}

/// Parses `otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=…&digits=…&period=…`.
pub fn parse_otpauth_uri(uri: &str) -> Result<TotpConfig> {
    let bad = VaultError::Invalid("not a valid otpauth://totp/ link");
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .or_else(|| uri.strip_prefix("otpauth://TOTP/"))
        .ok_or(bad.clone())?;
    let (label, query) = rest.split_once('?').ok_or(bad.clone())?;
    let label = percent_decode(label).ok_or(bad.clone())?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
        None => (None, label.trim().to_owned()),
    };
    let mut config = TotpConfig {
        secret: String::new(),
        algorithm: "SHA1".into(),
        digits: 6,
        period: 30,
        issuer: label_issuer,
        account: (!account.is_empty()).then_some(account),
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v).ok_or(bad.clone())?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => config.secret = v.to_ascii_uppercase().replace(' ', ""),
            "issuer" => config.issuer = Some(v),
            "algorithm" => config.algorithm = v.to_ascii_uppercase(),
            "digits" => config.digits = v.parse().map_err(|_| bad.clone())?,
            "period" => config.period = v.parse().map_err(|_| bad.clone())?,
            _ => {}
        }
    }
    Totp::from_config(&config)?;
    Ok(config)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secret_ascii: &[u8], alg: &str) -> TotpConfig {
        TotpConfig {
            secret: encode_base32(secret_ascii),
            algorithm: alg.into(),
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        }
    }

    fn encode_base32(data: &[u8]) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0u32);
        for &b in data {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((acc >> bits) & 31) as usize] as char);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let s1 = b"12345678901234567890".to_vec();
        let s256 = b"12345678901234567890123456789012".to_vec();
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let rows: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let t1 = Totp::from_config(&config(&s1, "SHA1")).unwrap();
        let t256 = Totp::from_config(&config(&s256, "SHA256")).unwrap();
        let t512 = Totp::from_config(&config(&s512, "SHA512")).unwrap();
        for (t, a, b, c) in rows {
            assert_eq!(t1.code_at(t).code, a, "SHA1 at {t}");
            assert_eq!(t256.code_at(t).code, b, "SHA256 at {t}");
            assert_eq!(t512.code_at(t).code, c, "SHA512 at {t}");
        }
    }

    #[test]
    fn remaining_seconds() {
        let t = Totp::from_config(&TotpConfig {
            digits: 6,
            ..config(b"12345678901234567890", "SHA1")
        })
        .unwrap();
        assert_eq!(t.code_at(59).seconds_remaining, 1);
        assert_eq!(t.code_at(60).seconds_remaining, 30);
        assert_eq!(t.code_at(59).code.len(), 6);
    }

    #[test]
    fn otpauth_parsing() {
        let c = parse_otpauth_uri(
            "otpauth://totp/Example%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example+Co&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(c.issuer.as_deref(), Some("Example Co"));
        assert_eq!(c.account.as_deref(), Some("alice@example.com"));
        assert_eq!(c.secret, "JBSWY3DPEHPK3PXP");
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DP").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=!!").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DP&digits=9").is_err());
    }

    #[test]
    fn invalid_configs_rejected() {
        let mut c = config(b"abc", "MD5");
        assert!(Totp::from_config(&c).is_err());
        c.algorithm = "SHA1".into();
        c.period = 5;
        assert!(Totp::from_config(&c).is_err());
        c.period = 30;
        c.secret = String::new();
        assert!(Totp::from_config(&c).is_err());
    }
}
