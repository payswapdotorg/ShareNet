//! Registry-issued identifiers and the deterministic id mint (C2-005).
//!
//! # Law: identifiers are REGISTRY-issued, never caller-supplied
//!
//! Every object the hosted Developer API names — an application, an
//! environment, a credential, a webhook registration, an emitted event, a
//! delivery record — is identified by a string the REGISTRY mints at creation.
//! Callers never choose ids (the architecture law: no caller-controlled
//! security facts; ids are lookups into registry truth). Parsing validates the
//! exact shape, so a malformed or cross-kind id simply never matches anything
//! and every dependent lookup fails closed.
//!
//! # Shape
//!
//! `<kind>_<16 lower-base32 chars>` — e.g. `app_a2c4xqmwzslpvnkr`. The 16
//! base32 characters encode the first 10 bytes (80 bits) of
//! `SHA-256(seed || kind_tag || counter_be64)` where `seed` is the
//! per-deployment 256-bit registry seed (held by the hosted service, C3-005)
//! and `counter` is a strictly monotonic registry-local counter. Consequences:
//!
//! - **stable**: an id is assigned exactly once and never re-derived or
//!   changed; the mint counter is part of the persisted snapshot.
//! - **unique**: distinct (kind, counter) inputs feed a cryptographic hash;
//!   uniqueness is additionally ASSERTED by the stores (a colliding mint
//!   result is returned as an error, never silently accepted).
//! - **non-enumerable**: without the deployment seed the id space reveals no
//!   ordering and no volume information (a sequential `app_000123` would).
//! - **deterministic for tests**: same seed + counter ⇒ same id, so the whole
//!   model is reproducible without any randomness source.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;

/// The per-deployment seed for id minting.
///
/// The hosted service (C3-005) generates this once at deployment time; tests
/// construct fixed seeds for reproducibility. The seed is NOT a protocol key
/// and grants no authority — it only shapes the id space.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySeed(#[serde(with = "serde_hex_32")] [u8; 32]);

impl RegistrySeed {
    /// A fixed seed (tests, fixtures, deterministic deployments).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        RegistrySeed(bytes)
    }

    /// A seed derived from two 128-bit halves (convenience for tests).
    pub fn from_u128_pair(hi: u128, lo: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&hi.to_be_bytes());
        bytes[16..].copy_from_slice(&lo.to_be_bytes());
        RegistrySeed(bytes)
    }
}

impl fmt::Debug for RegistrySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the seed itself (habit hygiene, same as key material).
        write!(f, "RegistrySeed(<redacted>)")
    }
}

/// The monotonic id mint: seed + counter → opaque, unique, stable ids.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdMint {
    seed: RegistrySeed,
    next_counter: u64,
}

impl IdMint {
    pub fn new(seed: RegistrySeed) -> Self {
        IdMint { seed, next_counter: 0 }
    }

    /// The next counter that will be consumed (snapshot/debug).
    pub fn next_counter(&self) -> u64 {
        self.next_counter
    }

    fn derive(&mut self, kind_tag: &[u8]) -> ([u8; 32], u64) {
        let counter = self.next_counter;
        self.next_counter = counter.checked_add(1).expect("id mint counter exhausted (2^64 mints)");
        let mut h = Sha256::new();
        h.update(self.seed.0);
        h.update(kind_tag);
        h.update(counter.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        (digest, counter)
    }

    /// Mint the next id for the given kind. Every call consumes a counter;
    /// ids across kinds never share a counter value (kind-tag separation).
    pub fn mint(&mut self, kind: IdKind) -> String {
        let (digest, _) = self.derive(kind.tag());
        let mut s = String::with_capacity(kind.prefix().len() + 17);
        s.push_str(kind.prefix());
        s.push('_');
        s.push_str(&base32_lower(&digest[..10]));
        s
    }

    /// Mint a 16-byte nonce for a namespace. Distinct namespaces (challenge
    /// nonces, webhook event nonces) pass distinct tags, and every tag is
    // separate from the id tags, so minted values never collide across
    /// namespaces; the replay guard additionally enforces uniqueness at
    /// verification time.
    pub fn mint_nonce(&mut self, namespace: NonceNamespace) -> [u8; 16] {
        let tag: &[u8] = match namespace {
            NonceNamespace::AuthChallenge => b"nonce/auth-challenge",
            NonceNamespace::WebhookEvent => b"nonce/webhook-event",
        };
        let (digest, _) = self.derive(tag);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }
}

/// The kinds of registry-issued identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdKind {
    App,
    Environment,
    Credential,
    Webhook,
    Event,
    Delivery,
}

/// The namespaces of minted nonces (distinct tag spaces).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceNamespace {
    /// Single-use developer-authentication challenge nonces.
    AuthChallenge,
    /// Webhook signed-event nonces (replay protection input).
    WebhookEvent,
}

impl IdKind {
    const fn prefix(self) -> &'static str {
        match self {
            IdKind::App => "app",
            IdKind::Environment => "env",
            IdKind::Credential => "cred",
            IdKind::Webhook => "wh",
            IdKind::Event => "evt",
            IdKind::Delivery => "dlv",
        }
    }

    const fn tag(self) -> &'static [u8] {
        match self {
            IdKind::App => b"id/app",
            IdKind::Environment => b"id/env",
            IdKind::Credential => b"id/cred",
            IdKind::Webhook => b"id/wh",
            IdKind::Event => b"id/evt",
            IdKind::Delivery => b"id/dlv",
        }
    }

    /// The character length of a minted id for this kind (prefix + 16).
    const fn id_len(self) -> usize {
        self.prefix().len() + 1 + 16
    }
}

/// Validate a minted id string for a kind: exact prefix + `_` + 16 chars of
/// the lower-base32 alphabet `a-z2-7`.
fn validate_id(s: &str, kind: IdKind) -> bool {
    let body = match s.strip_prefix(kind.prefix()) {
        Some(rest) => rest,
        None => return false,
    };
    let body = match body.strip_prefix('_') {
        Some(rest) => rest,
        None => return false,
    };
    body.len() == kind.id_len() - kind.prefix().len() - 1
        && body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// RFC 4648 lower-base32, no padding (10 bytes → 16 chars).
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Typed id newtypes (one per kind) — construction parses/validates, serde
// round-trips through the validated parse so a corrupt snapshot is rejected
// at restore time, not silently accepted.
// ---------------------------------------------------------------------------

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $kind:expr, $doc:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parse and validate a registry id of this kind.
            pub fn parse(s: &str) -> Result<Self, IdError> {
                if validate_id(s, $kind) {
                    Ok($name(s.to_owned()))
                } else {
                    Err(IdError::Malformed {
                        kind: $kind,
                        value: s.to_owned(),
                    })
                }
            }

            /// The validated id string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdError;
            fn try_from(s: &str) -> Result<Self, IdError> {
                Self::parse(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                $name::parse(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_newtype!(
    /// Stable registry-issued application id (`app_…`).
    AppId,
    IdKind::App,
    "app"
);
id_newtype!(
    /// Stable registry-issued environment id (`env_…`).
    EnvironmentId,
    IdKind::Environment,
    "env"
);
id_newtype!(
    /// Stable registry-issued credential id (`cred_…`).
    CredentialId,
    IdKind::Credential,
    "cred"
);
id_newtype!(
    /// Stable registry-issued webhook registration id (`wh_…`).
    WebhookId,
    IdKind::Webhook,
    "wh"
);
id_newtype!(
    /// Stable registry-issued event id (`evt_…`).
    EventId,
    IdKind::Event,
    "evt"
);
id_newtype!(
    /// Stable registry-issued delivery record id (`dlv_…`).
    DeliveryId,
    IdKind::Delivery,
    "dlv"
);

/// Errors of the id layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// A string did not parse as an id of the expected kind.
    Malformed { kind: IdKind, value: String },
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdError::Malformed { kind, value } => {
                write!(f, "malformed {} id: {:?}", kind.prefix(), value)
            }
        }
    }
}

impl std::error::Error for IdError {}

// --- hex (used by seeds, nonces, signatures and secrets) -------------------

/// Lowercase hex encode.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lowercase hex decode (rejects odd length, non-hex characters, mixed case).
pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, IdError> {
    if s.len() % 2 != 0 {
        return Err(IdError::Malformed { kind: IdKind::App, value: s.to_owned() });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0]);
        let lo = hex_val(pair[1]);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => return Err(IdError::Malformed { kind: IdKind::App, value: s.to_owned() }),
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

mod serde_hex_32 {
    use super::{hex_decode, hex_encode, IdError};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let bytes = hex_decode(&raw).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes).map_err(|_| {
            serde::de::Error::custom(IdError::Malformed { kind: super::IdKind::App, value: raw })
        })
    }
}

/// A `BTreeMap` wrapper that (de)serializes as a SEQUENCE of key/value
/// entries instead of a JSON map.
///
/// Why: the model's stores key state by tuples (`(AppId, EnvironmentId)`,
/// `(WebhookId, EventId)`, `(CredentialId, nonce)`, …) for total, ordered
/// lookups — but JSON map keys must be strings, so tuple-keyed maps cannot
/// round-trip through `serde_json` directly. This wrapper serializes the
/// map as `[[k, v], …]` (deterministically ordered — BTreeMap iteration),
/// rejects duplicate keys on restore (fail closed on corrupt snapshots),
/// and derefs to the inner map so store code stays unchanged.
#[derive(Clone, Debug)]
pub(crate) struct EntryMap<K: Ord, V>(pub BTreeMap<K, V>);

impl<K: Ord, V> Default for EntryMap<K, V> {
    fn default() -> Self {
        EntryMap(BTreeMap::new())
    }
}

impl<K, V> EntryMap<K, V>
where
    K: Ord,
{
    pub fn new() -> Self {
        EntryMap(BTreeMap::new())
    }
}

impl<K, V> std::ops::Deref for EntryMap<K, V>
where
    K: Ord,
{
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> std::ops::DerefMut for EntryMap<K, V>
where
    K: Ord,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> Serialize for EntryMap<K, V>
where
    K: Serialize + Ord,
    V: Serialize,
{
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let entries: Vec<(&K, &V)> = self.0.iter().collect();
        entries.serialize(s)
    }
}

impl<'de, K, V> Deserialize<'de> for EntryMap<K, V>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let entries: Vec<(K, V)> = Vec::deserialize(d)?;
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            if map.insert(k, v).is_some() {
                return Err(serde::de::Error::custom("duplicate key in snapshot"));
            }
        }
        Ok(EntryMap(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> IdMint {
        IdMint::new(RegistrySeed::from_u128_pair(0xC2, 0x005))
    }

    #[test]
    fn minted_ids_parse_for_their_kind() {
        let mut m = mint();
        let app = m.mint(IdKind::App);
        assert!(AppId::parse(&app).is_ok());
        assert!(EnvironmentId::parse(&app).is_err());
    }

    #[test]
    fn ids_are_stable_and_unique_across_kinds_and_counters() {
        let mut a = mint();
        let mut b = mint();
        let a1 = a.mint(IdKind::App);
        let a2 = a.mint(IdKind::App);
        let b1 = b.mint(IdKind::App);
        let a1_again = IdMint::new(RegistrySeed::from_u128_pair(0xC2, 0x005)).mint(IdKind::App);
        assert_ne!(a1, a2, "counter separation");
        assert_eq!(a1, b1, "same seed+counter ⇒ same id (determinism)");
        assert_eq!(a1, a1_again, "stability");
        assert_ne!(a.mint(IdKind::Webhook), a.mint(IdKind::Event));
    }

    #[test]
    fn different_seeds_produce_different_ids() {
        let mut x = IdMint::new(RegistrySeed::from_u128_pair(1, 1));
        let mut y = IdMint::new(RegistrySeed::from_u128_pair(1, 2));
        assert_ne!(x.mint(IdKind::App), y.mint(IdKind::App));
    }

    #[test]
    fn malformed_ids_fail_closed() {
        for bad in [
            "", "app", "app_", "app_short", "app_A234567890123456", // uppercase
            "app_a2c4xqmwzslpvnkr_extra", "xapp_a2c4xqmwzslpvnkr", " cred_abcdefghijklmnop",
        ] {
            assert!(AppId::parse(bad).is_err(), "{bad:?} must not parse");
        }
        assert!(AppId::parse("app_a2c4xqmwzslpvnkr").is_ok());
    }

    #[test]
    fn serde_rejects_malformed_ids_at_restore() {
        assert!(serde_json::from_str::<AppId>("\"app_a2c4xqmwzslpvnkr\"").is_ok());
        assert!(serde_json::from_str::<AppId>("\"app_bad\"").is_err());
        assert!(serde_json::from_str::<CredentialId>("\"app_a2c4xqmwzslpvnkr\"").is_err());
    }

    #[test]
    fn hex_round_trip_and_rejections() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_decode("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert!(hex_decode("0").is_err(), "odd length");
        assert!(hex_decode("0g").is_err(), "non-hex");
        assert!(hex_decode("0F").is_err(), "uppercase rejected (canonical form only)");
    }

    #[test]
    fn base32_shape_is_exact_length_and_alphabet() {
        let mut m = mint();
        let id = m.mint(IdKind::App);
        assert_eq!(id.len(), IdKind::App.id_len());
        assert!(id.starts_with("app_"));
        let body = &id[4..];
        assert_eq!(body.len(), 16);
        assert!(body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')));
    }

    #[test]
    fn minted_nonces_are_unique_within_and_across_namespaces() {
        let mut m = mint();
        assert_ne!(m.mint_nonce(NonceNamespace::AuthChallenge), m.mint_nonce(NonceNamespace::AuthChallenge));
        assert_ne!(m.mint_nonce(NonceNamespace::AuthChallenge), m.mint_nonce(NonceNamespace::WebhookEvent));
        // Determinism: same seed and same counter sequence ⇒ same nonces.
        let mut a = mint();
        let mut b = mint();
        assert_eq!(a.mint_nonce(NonceNamespace::WebhookEvent), b.mint_nonce(NonceNamespace::WebhookEvent));
    }

    #[test]
    fn seed_debug_never_leaks_material() {
        let dbg = format!("{:?}", RegistrySeed::from_u128_pair(9, 9));
        assert!(dbg.contains("redacted"));
    }
}
