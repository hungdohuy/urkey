//! KDF parameter decoding and unpadding: never panic; accepted values round-trip.
#![no_main]

use crypto_core::kdf::KdfParams;
use crypto_core::padding;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(params) = KdfParams::decode(data) {
        assert_eq!(&params.encode()[..], data);
    }
    if let Ok(body) = padding::unpad(data) {
        let again = padding::pad(&body);
        assert!(again.is_ok_and(|p| p.as_slice() == data));
    }
});
