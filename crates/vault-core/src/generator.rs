//! Password and passphrase generator (crypto design §11.2), using the OS CSPRNG with uniform
//! rejection sampling (no modulo bias). Required character classes are enforced by regenerating,
//! never by editing the output.

use zeroize::Zeroizing;

use crate::{Result, VaultError, rng};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Default symbol set.
pub const DEFAULT_SYMBOLS: &str = "!#$%&*+-.:;=?@^_~";
const LOOKALIKES: &[char] = &['l', 'I', '1', 'O', '0', 'o'];

static WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

fn words() -> impl Iterator<Item = &'static str> {
    WORDLIST.lines()
}

/// Options for random-character passwords.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    /// 8..=64.
    pub length: usize,
    /// Include at least one digit.
    pub digits: bool,
    /// Include at least one symbol.
    pub symbols: bool,
    /// Leave out `l I 1 O 0 o`.
    pub avoid_lookalikes: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            digits: true,
            symbols: true,
            avoid_lookalikes: false,
        }
    }
}

/// Options for passphrases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// 4..=10 words.
    pub words: usize,
    /// Separator between words.
    pub separator: String,
    /// Capitalize each word.
    pub capitalize: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
        }
    }
}

/// A generated secret and its estimated strength.
#[derive(PartialEq)]
pub struct Generated {
    /// The value (wiped on drop).
    pub value: Zeroizing<String>,
    /// Estimated entropy in bits (exact for the generation method).
    pub bits: f64,
}

impl core::fmt::Debug for Generated {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Generated")
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}

fn pick<T: Copy>(set: &[T]) -> Result<T> {
    let n = u32::try_from(set.len()).map_err(|_| VaultError::Invalid("set too large"))?;
    Ok(set[rng::below(n)? as usize])
}

/// Random-character password.
pub fn password(opts: &PasswordOptions) -> Result<Generated> {
    if !(8..=64).contains(&opts.length) {
        return Err(VaultError::Invalid("length must be 8–64"));
    }
    let keep = |c: &char| !opts.avoid_lookalikes || !LOOKALIKES.contains(c);
    let classes: Vec<Vec<char>> = [
        Some(LOWER),
        Some(UPPER),
        opts.digits.then_some(DIGITS),
        opts.symbols.then_some(DEFAULT_SYMBOLS),
    ]
    .into_iter()
    .flatten()
    .map(|s| s.chars().filter(keep).collect())
    .collect();
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let mut value = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            value.push(pick(&alphabet)?);
        }
        if classes
            .iter()
            .all(|class| value.chars().any(|c| class.contains(&c)))
        {
            let bits = opts.length as f64 * (alphabet.len() as f64).log2();
            return Ok(Generated { value, bits });
        }
    }
}

/// Word-list passphrase.
pub fn passphrase(opts: &PassphraseOptions) -> Result<Generated> {
    if !(4..=10).contains(&opts.words) {
        return Err(VaultError::Invalid("passphrases have 4–10 words"));
    }
    let list: Vec<&str> = words().collect();
    let mut value = Zeroizing::new(String::new());
    for i in 0..opts.words {
        if i > 0 {
            value.push_str(&opts.separator);
        }
        let word = pick(&list)?;
        if opts.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                value.extend(first.to_uppercase());
                value.push_str(chars.as_str());
            }
        } else {
            value.push_str(word);
        }
    }
    let bits = opts.words as f64 * (list.len() as f64).log2();
    Ok(Generated { value, bits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_complete() {
        let list: Vec<&str> = words().collect();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
    }

    #[test]
    fn password_respects_options() {
        for _ in 0..200 {
            let g = password(&PasswordOptions {
                length: 12,
                digits: true,
                symbols: false,
                avoid_lookalikes: true,
            })
            .unwrap();
            assert_eq!(g.value.chars().count(), 12);
            assert!(g.value.chars().any(|c| c.is_ascii_digit()));
            assert!(g.value.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(!g.value.chars().any(|c| LOOKALIKES.contains(&c)));
        }
        assert!(
            password(&PasswordOptions {
                length: 7,
                ..Default::default()
            })
            .is_err()
        );
        let g = password(&PasswordOptions::default()).unwrap();
        assert!(g.bits > 120.0);
    }

    #[test]
    fn passphrase_shape_and_strength() {
        let g = passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(g.value.split('-').count(), 6);
        assert!((g.bits - 77.5).abs() < 0.1);
        let c = passphrase(&PassphraseOptions {
            words: 4,
            separator: " ".into(),
            capitalize: true,
        })
        .unwrap();
        assert!(
            c.value
                .split(' ')
                .all(|w| w.chars().next().is_some_and(char::is_uppercase))
        );
    }

    /// Chi-squared uniformity of the sampler over 62 symbols (roadmap P2: χ² on 10⁶ samples).
    #[test]
    fn sampler_is_uniform() {
        let n: u32 = 62;
        let samples = 1_000_000u32;
        let mut counts = vec![0u32; n as usize];
        for _ in 0..samples {
            counts[rng::below(n).unwrap() as usize] += 1;
        }
        let expected = f64::from(samples) / f64::from(n);
        let chi2: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        // df = 61; P(chi2 > 110) ≈ 1e-4.
        assert!(chi2 < 110.0, "chi2 = {chi2}");
    }
}
