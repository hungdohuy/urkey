//! Arbitrary text as a Secret Key / Recovery Key: never panics; anything accepted round-trips.
#![no_main]

use crypto_core::encoding;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Ok(key) = encoding::parse_account_secret_key(text) {
        let again = encoding::parse_account_secret_key(&encoding::format_account_secret_key(&key));
        assert!(again.is_ok_and(|k| k.expose_secret() == key.expose_secret()));
    }
    if let Ok(key) = encoding::parse_recovery_key(text) {
        let again = encoding::parse_recovery_key(&encoding::format_recovery_key(&key));
        assert!(again.is_ok_and(|k| k.expose_secret() == key.expose_secret()));
    }
});
