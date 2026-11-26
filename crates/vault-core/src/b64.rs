//! base64url without padding, used for every binary field in JSON (data-model intro).

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::{Result, VaultError};

/// Encodes bytes as base64url without padding.
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes base64url without padding.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(text).map_err(|_| VaultError::Invalid("bad base64url"))
}

/// Decodes into a fixed-size array.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    decode(text)?
        .try_into()
        .map_err(|_| VaultError::Invalid("wrong length"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip_without_padding() {
        assert_eq!(super::encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(super::decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(super::decode("-_8=").is_err());
    }
}

/// Binary data that serializes as a base64url string. `Debug` shows only the length.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl core::fmt::Debug for B64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for B64 {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl serde::Serialize for B64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for B64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(d)?;
        decode(&text).map(Self).map_err(serde::de::Error::custom)
    }
}

impl B64 {
    /// Interprets the bytes as a fixed-size array.
    pub fn array<const N: usize>(&self) -> Result<[u8; N]> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Invalid("wrong length"))
    }
}
