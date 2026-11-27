//! Wire format (draft-miller-ssh-agent §3, §4). Frames are `uint32 length ‖ payload`, payload
//! starts with a message type byte.

use std::io::{Read, Write};

use vault_core::ssh::ssh_key::encoding::{Decode, Encode, Reader};
use vault_core::ssh::ssh_key::private::KeypairData;
use vault_core::ssh::ssh_key::{Comment, PrivateKey};

/// Largest frame accepted (OpenSSH uses 256 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

/// Message numbers.
pub mod msg {
    pub const FAILURE: u8 = 5;
    pub const SUCCESS: u8 = 6;
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_REQUEST: u8 = 13;
    pub const SIGN_RESPONSE: u8 = 14;
    pub const ADD_IDENTITY: u8 = 17;
    pub const REMOVE_IDENTITY: u8 = 18;
    pub const REMOVE_ALL_IDENTITIES: u8 = 19;
    pub const ADD_ID_CONSTRAINED: u8 = 25;
    pub const CONSTRAIN_LIFETIME: u8 = 1;
    pub const CONSTRAIN_CONFIRM: u8 = 2;
}

/// Protocol errors. Never contain key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The frame or message is malformed.
    #[error("malformed agent message")]
    Malformed,
    /// The frame exceeds [`MAX_FRAME`].
    #[error("agent message too large")]
    TooLarge,
    /// I/O failed or the peer closed the connection.
    #[error("connection closed")]
    Closed,
}

/// A parsed request.
pub enum Request {
    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    List,
    /// `SSH_AGENTC_SIGN_REQUEST`.
    Sign {
        /// Public key blob of the key to use.
        key_blob: Vec<u8>,
        /// Data to sign.
        data: Vec<u8>,
        /// Signature flags (only meaningful for RSA; ignored).
        flags: u32,
    },
    /// `SSH_AGENTC_ADD_IDENTITY` / `ADD_ID_CONSTRAINED`.
    Add {
        /// Decoded key.
        key: Box<PrivateKey>,
        /// Lifetime in seconds, if constrained.
        lifetime: Option<u32>,
        /// Per-use confirmation requested (not supported in V1; refused).
        confirm: bool,
    },
    /// `SSH_AGENTC_REMOVE_IDENTITY`.
    Remove {
        /// Public key blob.
        key_blob: Vec<u8>,
    },
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`.
    RemoveAll,
    /// Anything else (answered with `FAILURE`).
    Unsupported(u8),
}

/// Reads one frame's payload.
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, ProtocolError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).map_err(|_| ProtocolError::Closed)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(ProtocolError::Malformed);
    }
    if len > MAX_FRAME {
        return Err(ProtocolError::TooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(|_| ProtocolError::Closed)?;
    Ok(buf)
}

/// Writes one frame.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<(), ProtocolError> {
    let len = u32::try_from(payload.len()).map_err(|_| ProtocolError::TooLarge)?;
    w.write_all(&len.to_be_bytes())
        .map_err(|_| ProtocolError::Closed)?;
    w.write_all(payload).map_err(|_| ProtocolError::Closed)?;
    w.flush().map_err(|_| ProtocolError::Closed)
}

fn bytes(r: &mut &[u8]) -> Result<Vec<u8>, ProtocolError> {
    Vec::<u8>::decode(r).map_err(|_| ProtocolError::Malformed)
}

/// Parses a request payload.
pub fn parse_request(payload: &[u8]) -> Result<Request, ProtocolError> {
    let (&kind, mut rest) = payload.split_first().ok_or(ProtocolError::Malformed)?;
    let r = &mut rest;
    let req = match kind {
        msg::REQUEST_IDENTITIES => Request::List,
        msg::SIGN_REQUEST => Request::Sign {
            key_blob: bytes(r)?,
            data: bytes(r)?,
            flags: u32::decode(r).map_err(|_| ProtocolError::Malformed)?,
        },
        msg::ADD_IDENTITY | msg::ADD_ID_CONSTRAINED => {
            let keypair = KeypairData::decode(r).map_err(|_| ProtocolError::Malformed)?;
            let comment = String::decode(r).map_err(|_| ProtocolError::Malformed)?;
            let mut lifetime = None;
            let mut confirm = false;
            if kind == msg::ADD_ID_CONSTRAINED {
                while !r.is_finished() {
                    match u8::decode(r).map_err(|_| ProtocolError::Malformed)? {
                        msg::CONSTRAIN_LIFETIME => {
                            lifetime = Some(u32::decode(r).map_err(|_| ProtocolError::Malformed)?)
                        }
                        msg::CONSTRAIN_CONFIRM => confirm = true,
                        _ => return Err(ProtocolError::Malformed),
                    }
                }
            }
            let key = PrivateKey::new(keypair, Comment::from(comment))
                .map_err(|_| ProtocolError::Malformed)?;
            Request::Add {
                key: Box::new(key),
                lifetime,
                confirm,
            }
        }
        msg::REMOVE_IDENTITY => Request::Remove {
            key_blob: bytes(r)?,
        },
        msg::REMOVE_ALL_IDENTITIES => Request::RemoveAll,
        other => return Ok(Request::Unsupported(other)),
    };
    if !r.is_finished() {
        return Err(ProtocolError::Malformed);
    }
    Ok(req)
}

/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub fn identities_answer(ids: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![msg::IDENTITIES_ANSWER];
    let n = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&n.to_be_bytes());
    for (blob, comment) in ids {
        let _ = blob.as_slice().encode(&mut out);
        let _ = comment.as_str().encode(&mut out);
    }
    out
}

/// `SSH_AGENT_SIGN_RESPONSE`.
pub fn sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut out = vec![msg::SIGN_RESPONSE];
    let _ = signature_blob.encode(&mut out);
    out
}

/// Builds `ADD_ID_CONSTRAINED` with a lifetime (what `urk unlock` sends; same as `ssh-add -t`).
pub fn add_identity_request(
    key: &PrivateKey,
    lifetime_secs: u32,
) -> Result<Vec<u8>, ProtocolError> {
    let mut out = vec![msg::ADD_ID_CONSTRAINED];
    key.key_data()
        .encode(&mut out)
        .map_err(|_| ProtocolError::Malformed)?;
    key.comment()
        .as_str_lossy()
        .encode(&mut out)
        .map_err(|_| ProtocolError::Malformed)?;
    out.push(msg::CONSTRAIN_LIFETIME);
    out.extend_from_slice(&lifetime_secs.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_limits() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[msg::REQUEST_IDENTITIES]).unwrap();
        assert_eq!(buf, [0, 0, 0, 1, 11]);
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), vec![11]);
        let huge = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert_eq!(
            read_frame(&mut &huge[..]).unwrap_err(),
            ProtocolError::TooLarge
        );
        assert_eq!(
            read_frame(&mut &[0u8, 0, 0, 0][..]).unwrap_err(),
            ProtocolError::Malformed
        );
        assert_eq!(
            read_frame(&mut &[0u8, 0, 0, 5, 1][..]).unwrap_err(),
            ProtocolError::Closed
        );
    }

    #[test]
    fn parses_basic_requests() {
        assert!(matches!(parse_request(&[11]).unwrap(), Request::List));
        assert!(matches!(parse_request(&[19]).unwrap(), Request::RemoveAll));
        assert!(matches!(
            parse_request(&[99]).unwrap(),
            Request::Unsupported(99)
        ));
        assert!(parse_request(&[]).is_err());
        assert!(parse_request(&[11, 0]).is_err()); // trailing bytes
        let mut sign = vec![13];
        let _ = [1u8, 2].as_slice().encode(&mut sign);
        let _ = b"data".as_slice().encode(&mut sign);
        sign.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            parse_request(&sign).unwrap(),
            Request::Sign { flags: 0, .. }
        ));
        assert!(parse_request(&sign[..sign.len() - 1]).is_err());
    }

    #[test]
    fn identities_answer_layout() {
        let a = identities_answer(&[(vec![1, 2], "c".into())]);
        assert_eq!(a, [12, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 0, 0, 0, 1, b'c']);
    }
}
