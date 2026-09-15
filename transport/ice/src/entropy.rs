//! OS entropy for transaction ids and relay allocation nonces.
//!
//! Unix: `/dev/urandom`, read exactly. Non-unix: fail closed (the same
//! policy as the protocol core's identity seed entropy — no configured
//! entropy source in this wave, never a weak fallback).

use crate::error::IceError;

/// Fill `buf` with OS entropy.
#[cfg(unix)]
pub fn random_bytes(buf: &mut [u8]) -> Result<(), IceError> {
    use std::io::Read;
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(buf)
    })();
    result.map_err(|_| IceError::EntropyUnavailable)
}

/// Non-unix hosts have no configured entropy source; fail closed.
#[cfg(not(unix))]
pub fn random_bytes(_buf: &mut [u8]) -> Result<(), IceError> {
    Err(IceError::EntropyUnavailable)
}

/// A random 64-bit value (relay ALLOCATE nonces).
pub fn random_u64() -> Result<u64, IceError> {
    let mut b = [0u8; 8];
    random_bytes(&mut b)?;
    Ok(u64::from_be_bytes(b))
}
