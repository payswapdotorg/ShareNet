//! The webhook model: registration, delivery records, and SIGNED events
//! (C2-005, `spec/developer-integration.yaml`: `register_webhooks`,
//! `events`, `signed_webhooks`).
//!
//! # The signature scheme (normative — `sharenet-webhook-hmacsha256-v1`)
//!
//! **Algorithm.** `HMAC-SHA-256` keyed with the webhook's REGISTERED secret
//! (the symmetric secret the developer supplied at registration — the
//! GitHub/Stripe webhook pattern the contract names). Ed25519 is deliberately
//! NOT used here: it is the developer *authentication* key (asymmetric, the
//! registry holds only the public half), while webhook payloads are verified
//! by the developer's own receiver, which knows the secret. Same RustCrypto
//! palette as the rest of the repository; no new cryptographic primitives.
//!
//! **Canonicalization.** The signed bytes are a fixed-order, `\n`-joined
//! envelope over exactly these fields (no JSON of the envelope itself, no
//! field reordering ambiguity):
//!
//! ```text
//! sharenet.webhook.v1\n
//! <webhook_id>\n            e.g. wh_a2c4xqmwzslpvnkr
//! <event_id>\n              e.g. evt_…
//! <event_type>\n            one of the eight spec event names (snake_case)
//! <occurred_at_unix>\n      decimal u64
//! <nonce_hex>\n             16 bytes → 32 lowercase hex chars
//! <canonical_payload_json>\n
//! ```
//!
//! `<canonical_payload_json>` is written by [`write_canonical_json`]:
//! objects have lexicographically sorted keys, no insignificant whitespace,
//! integers only (no floats — floats are rejected at payload construction),
//! and strict JSON string escaping (`"`, `\`, and control characters).
//!
//! **Timestamp + nonce (replay protection).** `occurred_at` is bound into the
//! signed bytes; verification rejects events whose timestamp deviates from
//! the verifier's clock by more than [`DEFAULT_TIMESTAMP_TOLERANCE_SECS`]
//! (300s, either direction — bounds both replay and clock skew). The 16-byte
//! nonce is unique per emitted event; the [`ReplayGuard`] records every
//! successfully verified `(webhook_id, event_id) → nonce`, and any second
//! presentation of the same event is rejected ([`WebhookError::EventReplayed`]).
//! A verifier that wants idempotent retry handling across delivery re-sends
//! implements that AT ITS OWN layer on top of event_id; `verify_event` itself
//! is strictly single-verification.
//!
//! **Verification order (fail closed, cheap checks first).** registration
//! exists FOR THIS APP (cross-app webhook ids are simply unknown — no
//! oracle) → registration active → app active → environment active → scheme
//! string EXACT → event type subscribed → timestamp window → replay guard →
//! HMAC. A forged event fails one of these; a replayed one fails the guard.
//!
//! # Delivery model
//!
//! Emission creates a [`DeliveryRecord`] per subscribed webhook in state
//! `Pending`. The hosted service (C3-005) performs the actual HTTP delivery
//! and reports outcomes back: [`DeliveryOutcome::Delivered`], retryable
//! [`DeliveryOutcome::AttemptFailed`] (bounded exponential backoff, then
//! `Expired` after [`MAX_DELIVERY_ATTEMPTS`]), or [`DeliveryOutcome::Expired`].
//! There is NO transport in this crate — the model owns state and typing only.
//!
//! # Boundaries
//!
//! Webhook payloads are application-scoped event data. They never carry node
//! private keys, route/circuit internals or unrestricted network evidence
//! (ADR-006 forbidden shortcuts); the payload is caller-supplied opaque
//! canonical JSON validated exactly by its canonical type.

use crate::app::{AppRegistry, AppRegistryError, EnvironmentKind};
use crate::ids::{
    hex_encode, AppId, DeliveryId, EntryMap, EnvironmentId, EventId, IdMint, NonceNamespace,
    RegistrySeed, WebhookId,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The signature scheme identifier (carried in every signed event; verified
/// for an EXACT match — scheme confusion is a reject, not a downgrade).
pub const WEBHOOK_SIGNATURE_SCHEME: &str = "sharenet-webhook-hmacsha256-v1";

/// The canonical envelope prefix.
pub const WEBHOOK_ENVELOPE_PREFIX: &str = "sharenet.webhook.v1";

/// Default timestamp tolerance for event verification (seconds, both ways).
pub const DEFAULT_TIMESTAMP_TOLERANCE_SECS: u64 = 300;

/// Maximum delivery attempts before a delivery expires.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;

// ---------------------------------------------------------------------------
// Event types (exactly the eight of spec/developer-integration.yaml `events`)
// ---------------------------------------------------------------------------

/// The eight typed application events of `spec/developer-integration.yaml`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ConnectionChanged,
    GatewayChanged,
    RecoveryStarted,
    RecoveryCompleted,
    TransferProgress,
    ContributionVerified,
    PointsChanged,
    CapabilityChanged,
}

impl EventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventType::ConnectionChanged => "connection_changed",
            EventType::GatewayChanged => "gateway_changed",
            EventType::RecoveryStarted => "recovery_started",
            EventType::RecoveryCompleted => "recovery_completed",
            EventType::TransferProgress => "transfer_progress",
            EventType::ContributionVerified => "contribution_verified",
            EventType::PointsChanged => "points_changed",
            EventType::CapabilityChanged => "capability_changed",
        }
    }

    /// Parse the spec's event name (total: unknown names are errors).
    pub fn parse(s: &str) -> Result<Self, WebhookError> {
        match s {
            "connection_changed" => Ok(EventType::ConnectionChanged),
            "gateway_changed" => Ok(EventType::GatewayChanged),
            "recovery_started" => Ok(EventType::RecoveryStarted),
            "recovery_completed" => Ok(EventType::RecoveryCompleted),
            "transfer_progress" => Ok(EventType::TransferProgress),
            "contribution_verified" => Ok(EventType::ContributionVerified),
            "points_changed" => Ok(EventType::PointsChanged),
            "capability_changed" => Ok(EventType::CapabilityChanged),
            other => Err(WebhookError::UnknownEventType(other.to_owned())),
        }
    }

    /// All eight event types (iteration/telemetry).
    pub const ALL: [EventType; 8] = [
        EventType::ConnectionChanged,
        EventType::GatewayChanged,
        EventType::RecoveryStarted,
        EventType::RecoveryCompleted,
        EventType::TransferProgress,
        EventType::ContributionVerified,
        EventType::PointsChanged,
        EventType::CapabilityChanged,
    ];
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON payload value (integers only, sorted keys, strict escaping)
// ---------------------------------------------------------------------------

/// A canonical-JSON payload value. Integers only — floats do not exist in
/// the canonical payload model (deserialization rejects them; there is no
/// `f64`). Object keys serialize in lexicographic order (BTreeMap).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    /// Convenience constructor for an object.
    pub fn object(pairs: impl IntoIterator<Item = (String, CanonicalValue)>) -> Self {
        CanonicalValue::Object(pairs.into_iter().collect())
    }

    pub fn str(s: &str) -> Self {
        CanonicalValue::Str(s.to_owned())
    }

    pub fn int(v: i64) -> Self {
        CanonicalValue::Int(v)
    }

    /// Convert a parsed `serde_json::Value` into the canonical model.
    /// Rejects floats (and integers outside i64) — the canonical payload
    /// model is integer-only by construction.
    fn from_json_value(value: serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Null => Ok(CanonicalValue::Null),
            serde_json::Value::Bool(b) => Ok(CanonicalValue::Bool(b)),
            serde_json::Value::Number(n) => n
                .as_i64()
                .map(CanonicalValue::Int)
                .ok_or_else(|| "canonical payloads are integer-only (floats or out-of-i64 numbers rejected)".to_owned()),
            serde_json::Value::String(s) => Ok(CanonicalValue::Str(s)),
            serde_json::Value::Array(items) => items
                .into_iter()
                .map(CanonicalValue::from_json_value)
                .collect::<Result<Vec<_>, _>>()
                .map(CanonicalValue::Array),
            serde_json::Value::Object(map) => map
                .into_iter()
                .map(|(k, v)| CanonicalValue::from_json_value(v).map(|v| (k, v)))
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map(CanonicalValue::Object),
        }
    }
}

// CanonicalValue (de)serializes AS plain JSON (an Object IS a JSON object —
// not an enum-tagged form), so signed-event payloads are exactly the JSON a
// developer's receiver parses.
impl Serialize for CanonicalValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CanonicalValue::Null => serializer.serialize_none(),
            CanonicalValue::Bool(b) => serializer.serialize_bool(*b),
            CanonicalValue::Int(i) => serializer.serialize_i64(*i),
            CanonicalValue::Str(s) => serializer.serialize_str(s),
            CanonicalValue::Array(items) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            CanonicalValue::Object(map) => {
                use serde::ser::SerializeMap;
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(d)?;
        CanonicalValue::from_json_value(value).map_err(serde::de::Error::custom)
    }
}

/// Write the canonical JSON form: no whitespace, sorted object keys, strict
/// string escaping. Deterministic by construction — the same value always
/// produces byte-identical output (this is what gets signed).
pub fn write_canonical_json(value: &CanonicalValue, out: &mut String) {
    match value {
        CanonicalValue::Null => out.push_str("null"),
        CanonicalValue::Bool(true) => out.push_str("true"),
        CanonicalValue::Bool(false) => out.push_str("false"),
        CanonicalValue::Int(v) => out.push_str(&v.to_string()),
        CanonicalValue::Str(s) => write_escaped_json_string(s, out),
        CanonicalValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        CanonicalValue::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_escaped_json_string(k, out);
                out.push(':');
                write_canonical_json(v, out);
            }
            out.push('}');
        }
    }
}

/// Canonical JSON as an owned string.
pub fn canonical_json(value: &CanonicalValue) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_escaped_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Webhook secret (zeroized, hex-serialized)
// ---------------------------------------------------------------------------

/// The webhook signing secret (symmetric). Registered by the developer;
/// held by the registry to SIGN outgoing events; never exposed through any
/// read API (zeroized on drop, debug-redacted).
pub struct WebhookSecret(Vec<u8>);

impl WebhookSecret {
    /// Construct a secret (16..=256 bytes — enforced).
    pub fn new(bytes: Vec<u8>) -> Result<Self, WebhookError> {
        if bytes.len() < 16 || bytes.len() > 256 {
            return Err(WebhookError::InvalidSecretLength(bytes.len()));
        }
        Ok(WebhookSecret(bytes))
    }

    /// The raw secret bytes (internal: signing and verification only).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for WebhookSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebhookSecret(<redacted, {} bytes>)", self.0.len())
    }
}

impl Clone for WebhookSecret {
    fn clone(&self) -> Self {
        WebhookSecret(self.0.clone())
    }
}

impl Serialize for WebhookSecret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for WebhookSecret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(d)?;
        let bytes = crate::ids::hex_decode(&hex).map_err(serde::de::Error::custom)?;
        WebhookSecret::new(bytes).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Registration + delivery records
// ---------------------------------------------------------------------------

/// Lifecycle status of a webhook registration.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WebhookStatus {
    Active,
    Revoked { at: u64, reason: String },
}

/// A webhook registration: URL + event types + secret, scoped to exactly one
/// (app, environment). The registration is the ONLY truth for what a
/// receiver may be sent and how it is signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookRegistration {
    pub webhook_id: WebhookId,
    pub app_id: AppId,
    pub environment_id: EnvironmentId,
    pub url: String,
    pub event_types: BTreeSet<EventType>,
    pub secret: WebhookSecret,
    pub created_at: u64,
    pub status: WebhookStatus,
}

impl WebhookRegistration {
    pub fn is_active(&self) -> bool {
        matches!(self.status, WebhookStatus::Active)
    }

    pub fn subscribes(&self, event: EventType) -> bool {
        self.event_types.contains(&event)
    }
}

/// Typed delivery outcome (reported by the hosted delivery worker, C3-005).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeliveryOutcome {
    Delivered { http_status: u16 },
    AttemptFailed { reason: String },
    Expired { reason: String },
}

/// The state machine of one delivery attempt sequence.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Emitted, not yet attempted.
    Pending,
    /// Terminal success.
    Delivered { at: u64, http_status: u16 },
    /// Attempt failed; retry scheduled (or the record expires after
    /// [`MAX_DELIVERY_ATTEMPTS`] attempts).
    Failed { attempts: u32, last_at: u64, last_reason: String, next_attempt_at: u64 },
    /// Terminal failure (max attempts, TTL, or explicit expiry).
    Expired { at: u64, reason: String },
}

impl DeliveryState {
    /// Deterministic bounded backoff after the k-th failed attempt.
    pub fn backoff_secs(attempts: u32) -> u64 {
        // 60s, 120s, 240s, 480s, ... capped at 1 hour.
        let shift = attempts.saturating_sub(1).min(16);
        60u64.saturating_mul(1u64 << shift).min(3600)
    }
}

/// A delivery record for one (webhook, event) emission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub delivery_id: DeliveryId,
    pub webhook_id: WebhookId,
    pub event_id: EventId,
    pub event_type: EventType,
    pub created_at: u64,
    pub state: DeliveryState,
}

impl DeliveryRecord {
    /// Attempts so far (0 for pending/delivered/expired-without-attempt).
    pub fn attempts(&self) -> u32 {
        match self.state {
            DeliveryState::Failed { attempts, .. } => attempts,
            _ => 0,
        }
    }

    /// Whether the delivery is due for (re)attempt at `now`.
    pub fn is_due(&self, now: u64) -> bool {
        match &self.state {
            DeliveryState::Pending => true,
            DeliveryState::Failed { next_attempt_at, .. } => now >= *next_attempt_at,
            _ => false,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, DeliveryState::Delivered { .. } | DeliveryState::Expired { .. })
    }
}

/// An emitted signed event plus its delivery record id.
#[derive(Clone, Debug)]
pub struct EmittedWebhookEvent {
    pub signed_event: SignedEvent,
    pub delivery_id: DeliveryId,
}

// ---------------------------------------------------------------------------
// Signed events
// ---------------------------------------------------------------------------

/// A signed webhook event. The signature is HMAC-SHA-256 over
/// [`canonical_event_bytes`] with the registration's secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedEvent {
    pub scheme: String,
    pub event_id: EventId,
    pub webhook_id: WebhookId,
    pub event_type: EventType,
    pub occurred_at: u64,
    pub nonce: [u8; 16],
    pub payload: CanonicalValue,
    pub signature: [u8; 32],
}

impl SignedEvent {
    /// The canonical signed bytes (the envelope documented at the module
    /// head). Deterministic; the ONLY bytes covered by the signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(160);
        out.push_str(WEBHOOK_ENVELOPE_PREFIX);
        out.push('\n');
        out.push_str(self.webhook_id.as_str());
        out.push('\n');
        out.push_str(self.event_id.as_str());
        out.push('\n');
        out.push_str(self.event_type.as_str());
        out.push('\n');
        out.push_str(&self.occurred_at.to_string());
        out.push('\n');
        out.push_str(&hex_encode(&self.nonce));
        out.push('\n');
        write_canonical_json(&self.payload, &mut out);
        out.push('\n');
        out.into_bytes()
    }
}

impl fmt::Debug for SignedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedEvent")
            .field("scheme", &self.scheme)
            .field("event_id", &self.event_id)
            .field("webhook_id", &self.webhook_id)
            .field("event_type", &self.event_type)
            .field("occurred_at", &self.occurred_at)
            .field("nonce", &hex_encode(&self.nonce))
            .field("payload", &self.payload)
            .field("signature", &hex_encode(&self.signature))
            .finish()
    }
}

impl Serialize for SignedEvent {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("SignedEvent", 8)?;
        st.serialize_field("scheme", &self.scheme)?;
        st.serialize_field("event_id", &self.event_id)?;
        st.serialize_field("webhook_id", &self.webhook_id)?;
        st.serialize_field("event_type", &self.event_type)?;
        st.serialize_field("occurred_at", &self.occurred_at)?;
        st.serialize_field("nonce", &hex_encode(&self.nonce))?;
        st.serialize_field("payload", &self.payload)?;
        st.serialize_field("signature", &hex_encode(&self.signature))?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for SignedEvent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            scheme: String,
            event_id: EventId,
            webhook_id: WebhookId,
            event_type: EventType,
            occurred_at: u64,
            nonce: String,
            payload: CanonicalValue,
            signature: String,
        }
        let raw = Raw::deserialize(d)?;
        let nonce_bytes = crate::ids::hex_decode(&raw.nonce).map_err(serde::de::Error::custom)?;
        let nonce: [u8; 16] = nonce_bytes.try_into().map_err(|_| {
            serde::de::Error::custom("nonce must be exactly 16 bytes (32 hex chars)")
        })?;
        let sig_bytes = crate::ids::hex_decode(&raw.signature).map_err(serde::de::Error::custom)?;
        let signature: [u8; 32] = sig_bytes.try_into().map_err(|_| {
            serde::de::Error::custom("signature must be exactly 32 bytes (64 hex chars)")
        })?;
        Ok(SignedEvent {
            scheme: raw.scheme,
            event_id: raw.event_id,
            webhook_id: raw.webhook_id,
            event_type: raw.event_type,
            occurred_at: raw.occurred_at,
            nonce,
            payload: raw.payload,
            signature,
        })
    }
}

/// Compute the event signature (HMAC-SHA-256 over the canonical bytes).
pub fn sign_event_bytes(secret: &WebhookSecret, canonical_bytes: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length; secret length validated at construction");
    mac.update(canonical_bytes);
    mac.finalize().into_bytes().into()
}

// ---------------------------------------------------------------------------
// Replay guard
// ---------------------------------------------------------------------------

/// Records every successfully verified `(webhook_id, event_id) → nonce`.
/// A second presentation of the same event is a REPLAY and is rejected.
/// Entries older than the timestamp window can never verify again (they fail
/// the window check first), so pruning by `verified_at` is behavior-safe.
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct ReplayGuard {
    seen: EntryMap<(WebhookId, EventId), ([u8; 16], u64)>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        ReplayGuard::default()
    }

    /// Reject a replay BEFORE inserting: true if the event was already seen.
    pub fn is_replay(&self, webhook: &WebhookId, event: &EventId) -> bool {
        self.seen.contains_key(&(webhook.clone(), event.clone()))
    }

    /// Record a successful verification.
    pub fn record(&mut self, webhook: WebhookId, event: EventId, nonce: [u8; 16], at: u64) {
        self.seen.insert((webhook, event), (nonce, at));
    }

    /// Drop entries whose verification window has long passed.
    pub fn prune(&mut self, now: u64, tolerance_secs: u64) {
        self.seen.retain(|_, (_, verified_at)| {
            now.saturating_sub(*verified_at) <= tolerance_secs * 2
        });
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors of the webhook model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookError {
    UnknownWebhook(WebhookId),
    WebhookRevoked(WebhookId),
    AppRevoked(AppId),
    EnvironmentRevoked(crate::ids::EnvironmentId),
    /// The URL was rejected (reason included; see `validate_webhook_url`).
    InvalidUrl(String),
    /// The event name is not one of the eight spec event types.
    UnknownEventType(String),
    /// The secret length is out of the 16..=256 byte range.
    InvalidSecretLength(usize),
    /// A registration must subscribe to at least one event type.
    NoEventTypes,
    /// The scheme string is not exactly `sharenet-webhook-hmacsha256-v1`.
    SchemeMismatch(String),
    /// The webhook is not subscribed to this event type.
    EventNotSubscribed(EventType),
    /// The event timestamp is outside the verification window.
    TimestampOutOfWindow { occurred_at: u64, now: u64, tolerance_secs: u64 },
    /// The event (webhook_id, event_id) was already verified — replay.
    EventReplayed,
    /// The HMAC did not verify under the registered secret.
    InvalidSignature,
    UnknownDelivery(DeliveryId),
    /// The delivery state machine rejects this transition.
    InvalidTransition(String),
    Registry(AppRegistryError),
    IdCollision(String),
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebhookError::UnknownWebhook(w) => write!(f, "unknown webhook: {w}"),
            WebhookError::WebhookRevoked(w) => write!(f, "webhook revoked: {w}"),
            WebhookError::AppRevoked(a) => write!(f, "app revoked: {a}"),
            WebhookError::EnvironmentRevoked(e) => write!(f, "environment revoked: {e}"),
            WebhookError::InvalidUrl(reason) => write!(f, "invalid webhook url: {reason}"),
            WebhookError::UnknownEventType(t) => write!(f, "unknown event type: {t}"),
            WebhookError::InvalidSecretLength(n) => {
                write!(f, "invalid webhook secret length: {n} (16..=256 bytes)")
            }
            WebhookError::NoEventTypes => f.write_str("webhook must subscribe to at least one event type"),
            WebhookError::SchemeMismatch(s) => write!(f, "signature scheme mismatch: {s}"),
            WebhookError::EventNotSubscribed(t) => write!(f, "webhook not subscribed to {t}"),
            WebhookError::TimestampOutOfWindow { occurred_at, now, tolerance_secs } => {
                write!(f, "event timestamp {occurred_at} out of window at now={now} (±{tolerance_secs}s)")
            }
            WebhookError::EventReplayed => f.write_str("event replay detected"),
            WebhookError::InvalidSignature => f.write_str("invalid webhook signature"),
            WebhookError::UnknownDelivery(d) => write!(f, "unknown delivery: {d}"),
            WebhookError::InvalidTransition(reason) => write!(f, "invalid delivery transition: {reason}"),
            WebhookError::Registry(e) => write!(f, "registry: {e}"),
            WebhookError::IdCollision(id) => write!(f, "id mint collision on {id}"),
        }
    }
}

impl std::error::Error for WebhookError {}

// ---------------------------------------------------------------------------
// The webhook store
// ---------------------------------------------------------------------------

/// The webhook store: registrations, delivery records, replay guard.
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookStore {
    mint: IdMint,
    webhooks: BTreeMap<WebhookId, WebhookRegistration>,
    deliveries: BTreeMap<DeliveryId, DeliveryRecord>,
    replay_guard: ReplayGuard,
    timestamp_tolerance_secs: u64,
}

impl WebhookStore {
    /// A store with the fixed well-known TEST seed (deterministic ids).
    pub fn new() -> Self {
        WebhookStore::with_seed(RegistrySeed::from_u128_pair(0x5a_e5, 0x11_a3))
    }

    pub fn with_seed(seed: RegistrySeed) -> Self {
        WebhookStore {
            mint: IdMint::new(seed),
            webhooks: BTreeMap::new(),
            deliveries: BTreeMap::new(),
            replay_guard: ReplayGuard::new(),
            timestamp_tolerance_secs: DEFAULT_TIMESTAMP_TOLERANCE_SECS,
        }
    }

    pub fn timestamp_tolerance_secs(&self) -> u64 {
        self.timestamp_tolerance_secs
    }

    pub fn set_timestamp_tolerance_secs(&mut self, secs: u64) {
        self.timestamp_tolerance_secs = secs.max(1);
    }

    pub fn replay_guard(&self) -> &ReplayGuard {
        &self.replay_guard
    }

    /// `register_webhooks`: URL + event types + secret, scoped to an active
    /// (app, environment). The URL policy: `https` always; `http` only for
    /// non-production environments; no userinfo; no fragments; bounded
    /// length; no control characters.
    pub fn register(
        &mut self,
        apps: &AppRegistry,
        app: &AppId,
        env: &crate::ids::EnvironmentId,
        url: &str,
        event_types: BTreeSet<EventType>,
        secret: WebhookSecret,
        at: u64,
    ) -> Result<WebhookRegistration, WebhookError> {
        if event_types.is_empty() {
            return Err(WebhookError::NoEventTypes);
        }
        let env_record = apps
            .active_environment(app, env)
            .map_err(WebhookError::Registry)?;
        validate_webhook_url(url, env_record.kind)?;
        let webhook_id = WebhookId::parse(&self.mint.mint(crate::ids::IdKind::Webhook))
            .expect("minted ids are well-formed by construction");
        let registration = WebhookRegistration {
            webhook_id: webhook_id.clone(),
            app_id: app.clone(),
            environment_id: env.clone(),
            url: url.to_owned(),
            event_types,
            secret,
            created_at: at,
            status: WebhookStatus::Active,
        };
        if self.webhooks.insert(webhook_id.clone(), registration.clone()).is_some() {
            return Err(WebhookError::IdCollision(webhook_id.to_string()));
        }
        Ok(registration)
    }

    /// Revoke a webhook registration (terminal).
    pub fn revoke(&mut self, webhook: &WebhookId, reason: &str, at: u64) -> Result<(), WebhookError> {
        let registration = self
            .webhooks
            .get_mut(webhook)
            .ok_or_else(|| WebhookError::UnknownWebhook(webhook.clone()))?;
        if registration.is_active() {
            registration.status = WebhookStatus::Revoked { at, reason: reason.to_owned() };
        }
        Ok(())
    }

    /// A registration, whatever its status (audit view). NOT app-scoped —
    /// the app-scoped read path is [`WebhookStore::registration_for_app`].
    pub fn registration(&self, webhook: &WebhookId) -> Option<&WebhookRegistration> {
        self.webhooks.get(webhook)
    }

    /// The app-scoped lookup: app A can never see app B's registrations —
    /// a cross-app webhook id is simply unknown (no oracle).
    pub fn registration_for_app(
        &self,
        app: &AppId,
        webhook: &WebhookId,
    ) -> Option<&WebhookRegistration> {
        self.webhooks.get(webhook).filter(|r| r.app_id == *app)
    }

    /// All registrations of one app (the app-scoped audit list).
    pub fn registrations_for_app(&self, app: &AppId) -> Vec<&WebhookRegistration> {
        self.webhooks.values().filter(|r| r.app_id == *app).collect()
    }

    /// Emit an event to every ACTIVE registration of (app, environment)
    /// subscribed to `event_type`. Creates one signed event + one Pending
    /// delivery record per registration. No subscribers ⇒ empty vec (not an
    /// error). Signing uses each registration's OWN secret.
    pub fn emit_event(
        &mut self,
        apps: &AppRegistry,
        app: &AppId,
        env: &crate::ids::EnvironmentId,
        event_type: EventType,
        payload: CanonicalValue,
        now: u64,
    ) -> Result<Vec<EmittedWebhookEvent>, WebhookError> {
        apps.active_app(app).map_err(WebhookError::Registry)?;
        apps.active_environment(app, env).map_err(WebhookError::Registry)?;
        let targets: Vec<WebhookRegistration> = self
            .webhooks
            .values()
            .filter(|r| r.app_id == *app && r.environment_id == *env && r.is_active())
            .filter(|r| r.subscribes(event_type))
            .cloned()
            .collect();
        let mut emitted = Vec::with_capacity(targets.len());
        for registration in targets {
            let event_id = EventId::parse(&self.mint.mint(crate::ids::IdKind::Event))
                .expect("minted ids are well-formed by construction");
            let nonce = self.mint.mint_nonce(NonceNamespace::WebhookEvent);
            let mut signed = SignedEvent {
                scheme: WEBHOOK_SIGNATURE_SCHEME.to_owned(),
                event_id: event_id.clone(),
                webhook_id: registration.webhook_id.clone(),
                event_type,
                occurred_at: now,
                nonce,
                payload: payload.clone(),
                signature: [0u8; 32],
            };
            signed.signature = sign_event_bytes(&registration.secret, &signed.canonical_bytes());
            let delivery_id =
                DeliveryId::parse(&self.mint.mint(crate::ids::IdKind::Delivery))
                    .expect("minted ids are well-formed by construction");
            let record = DeliveryRecord {
                delivery_id: delivery_id.clone(),
                webhook_id: registration.webhook_id.clone(),
                event_id: event_id.clone(),
                event_type,
                created_at: now,
                state: DeliveryState::Pending,
            };
            if self.deliveries.insert(delivery_id.clone(), record).is_some() {
                return Err(WebhookError::IdCollision(delivery_id.to_string()));
            }
            emitted.push(EmittedWebhookEvent { signed_event: signed, delivery_id });
        }
        Ok(emitted)
    }

    /// Verify a signed event presented under `app`'s context. Fail-closed
    /// order: registration (app-scoped, no cross-app oracle) → registration
    /// active → app active → environment active → scheme exact → event
    /// subscribed → timestamp window → replay guard → HMAC. The replay guard
    /// is only recorded on SUCCESS (a failed verification cannot poison a
    /// legitimate event id).
    pub fn verify_event(
        &mut self,
        apps: &AppRegistry,
        app: &AppId,
        signed: &SignedEvent,
        now: u64,
    ) -> Result<(), WebhookError> {
        let registration = self
            .registration_for_app(app, &signed.webhook_id)
            .ok_or_else(|| WebhookError::UnknownWebhook(signed.webhook_id.clone()))?;
        if !registration.is_active() {
            return Err(WebhookError::WebhookRevoked(signed.webhook_id.clone()));
        }
        apps.active_app(&registration.app_id)
            .map_err(|_| WebhookError::AppRevoked(registration.app_id.clone()))?;
        apps.active_environment(&registration.app_id, &registration.environment_id)
            .map_err(|_| WebhookError::EnvironmentRevoked(registration.environment_id.clone()))?;
        if signed.scheme != WEBHOOK_SIGNATURE_SCHEME {
            return Err(WebhookError::SchemeMismatch(signed.scheme.clone()));
        }
        if !registration.subscribes(signed.event_type) {
            return Err(WebhookError::EventNotSubscribed(signed.event_type));
        }
        let drift = now.abs_diff(signed.occurred_at);
        if drift > self.timestamp_tolerance_secs {
            return Err(WebhookError::TimestampOutOfWindow {
                occurred_at: signed.occurred_at,
                now,
                tolerance_secs: self.timestamp_tolerance_secs,
            });
        }
        if self.replay_guard.is_replay(&signed.webhook_id, &signed.event_id) {
            return Err(WebhookError::EventReplayed);
        }
        let expected = sign_event_bytes(&registration.secret, &signed.canonical_bytes());
        if expected != signed.signature {
            return Err(WebhookError::InvalidSignature);
        }
        self.replay_guard
            .record(signed.webhook_id.clone(), signed.event_id.clone(), signed.nonce, now);
        Ok(())
    }

    // --- delivery record API (the hosted worker's reporting surface) -------

    /// Report a delivery outcome for a record (the typed state machine).
    pub fn record_outcome(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        at: u64,
    ) -> Result<DeliveryRecord, WebhookError> {
        let record = self
            .deliveries
            .get_mut(delivery)
            .ok_or_else(|| WebhookError::UnknownDelivery(delivery.clone()))?;
        let new_state = match (&record.state, &outcome) {
            (DeliveryState::Pending, DeliveryOutcome::Delivered { http_status }) => {
                DeliveryState::Delivered { at, http_status: *http_status }
            }
            (DeliveryState::Pending, DeliveryOutcome::AttemptFailed { reason }) => {
                record_failure(1, at, reason.clone())
            }
            (DeliveryState::Failed { attempts, .. }, DeliveryOutcome::AttemptFailed { reason }) => {
                record_failure(*attempts + 1, at, reason.clone())
            }
            (
                DeliveryState::Failed { attempts, .. },
                DeliveryOutcome::Delivered { http_status },
            ) if *attempts < MAX_DELIVERY_ATTEMPTS => {
                DeliveryState::Delivered { at, http_status: *http_status }
            }
            (DeliveryState::Pending, DeliveryOutcome::Expired { reason }) => {
                DeliveryState::Expired { at, reason: reason.clone() }
            }
            (state, _) => {
                return Err(WebhookError::InvalidTransition(format!(
                    "outcome {:?} on state {state:?}",
                    DeliveryOutcomeKind::of(&outcome)
                )))
            }
        };
        record.state = new_state;
        Ok(record.clone())
    }

    /// A delivery record (audit view).
    pub fn delivery(&self, delivery: &DeliveryId) -> Option<&DeliveryRecord> {
        self.deliveries.get(delivery)
    }

    /// Deliveries of one app (app-scoped audit list).
    pub fn deliveries_for_app(&self, app: &AppId) -> Vec<&DeliveryRecord> {
        let webhook_ids: BTreeSet<WebhookId> =
            self.webhooks.values().filter(|r| r.app_id == *app).map(|r| r.webhook_id.clone()).collect();
        self.deliveries
            .values()
            .filter(|d| webhook_ids.contains(&d.webhook_id))
            .collect()
    }

    /// Deliveries due for (re)attempt at `now` (the worker's queue).
    pub fn pending_due(&self, now: u64) -> Vec<DeliveryId> {
        self.deliveries
            .values()
            .filter(|d| d.is_due(now))
            .map(|d| d.delivery_id.clone())
            .collect()
    }

    /// Prune stale replay-guard entries (state hygiene; behavior-safe since
    /// pruned events can no longer pass the timestamp window anyway).
    pub fn prune(&mut self, now: u64) {
        self.replay_guard.prune(now, self.timestamp_tolerance_secs);
    }
}

impl Default for WebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
enum DeliveryOutcomeKind {
    Delivered,
    AttemptFailed,
    Expired,
}

impl DeliveryOutcomeKind {
    fn of(outcome: &DeliveryOutcome) -> Self {
        match outcome {
            DeliveryOutcome::Delivered { .. } => DeliveryOutcomeKind::Delivered,
            DeliveryOutcome::AttemptFailed { .. } => DeliveryOutcomeKind::AttemptFailed,
            DeliveryOutcome::Expired { .. } => DeliveryOutcomeKind::Expired,
        }
    }
}

fn record_failure(attempts: u32, at: u64, reason: String) -> DeliveryState {
    if attempts >= MAX_DELIVERY_ATTEMPTS {
        DeliveryState::Expired { at, reason: format!("max attempts ({MAX_DELIVERY_ATTEMPTS}): {reason}") }
    } else {
        DeliveryState::Failed {
            attempts,
            last_at: at,
            last_reason: reason,
            next_attempt_at: at.saturating_add(DeliveryState::backoff_secs(attempts)),
        }
    }
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// Webhook URL policy: `https` everywhere; `http` allowed only in
/// non-production environments; a non-empty host; no userinfo (`@` before
/// the path); no fragments; no whitespace/control characters; ≤ 2048 chars.
pub fn validate_webhook_url(url: &str, env_kind: EnvironmentKind) -> Result<(), WebhookError> {
    let invalid = |reason: &str| Err(WebhookError::InvalidUrl(reason.to_owned()));
    if url.len() > 2048 {
        return invalid("longer than 2048 characters");
    }
    if url.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) {
        return invalid("contains whitespace or control characters");
    }
    let (scheme, rest) = match url.split_once("://") {
        Some(parts) => parts,
        None => return invalid("missing scheme"),
    };
    match scheme {
        "https" => {}
        "http" if env_kind != EnvironmentKind::Prod => {}
        "http" => return invalid("http URLs are not allowed in prod environments"),
        other => return invalid(&format!("unsupported scheme: {other}")),
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return invalid("empty host");
    }
    if authority.contains('@') {
        return invalid("userinfo in authority is not allowed");
    }
    if url.contains('#') {
        return invalid("fragments are not allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppProfile, AppRegistry, EnvironmentKind};
    use crate::ids::EnvironmentId;

    fn setup() -> (AppRegistry, WebhookStore, AppId, EnvironmentId) {
        let mut apps = AppRegistry::new();
        let app = apps
            .create_app("field-app", &[AppProfile::Participant], 1_000)
            .unwrap()
            .app_id
            .clone();
        let env = apps
            .create_environment(&app, EnvironmentKind::Prod, 1_010)
            .unwrap()
            .environment_id
            .clone();
        (apps, WebhookStore::new(), app, env)
    }

    fn register(
        store: &mut WebhookStore,
        apps: &AppRegistry,
        app: &AppId,
        env: &EnvironmentId,
        url: &str,
        events: &[EventType],
        secret: &str,
    ) -> WebhookRegistration {
        store
            .register(
                apps,
                app,
                env,
                url,
                events.iter().copied().collect(),
                WebhookSecret::new(secret.as_bytes().to_vec()).unwrap(),
                1_100,
            )
            .unwrap()
    }

    fn payload() -> CanonicalValue {
        CanonicalValue::object([
            ("session".to_owned(), CanonicalValue::Str("sess_1".to_owned())),
            ("state".to_owned(), CanonicalValue::Str("connected".to_owned())),
            ("gateway".to_owned(), CanonicalValue::Str("gw_9".to_owned())),
        ])
    }

    #[test]
    fn event_types_match_the_spec_exactly() {
        for name in [
            "connection_changed", "gateway_changed", "recovery_started", "recovery_completed",
            "transfer_progress", "contribution_verified", "points_changed", "capability_changed",
        ] {
            assert_eq!(EventType::parse(name).unwrap().as_str(), name);
        }
        assert_eq!(EventType::ALL.len(), 8);
        assert!(EventType::parse("connection_closed").is_err());
        assert!(EventType::parse("CONNECTION_CHANGED").is_err());
    }

    #[test]
    fn canonical_json_is_sorted_and_strict() {
        let value = CanonicalValue::object([
            ("zebra".to_owned(), CanonicalValue::Int(1)),
            ("alpha".to_owned(), CanonicalValue::Bool(true)),
            ("nested".to_owned(), CanonicalValue::Array(vec![CanonicalValue::Str("a\"b\\c\n".to_owned()), CanonicalValue::Int(-5)])),
        ]);
        let json = canonical_json(&value);
        assert_eq!(json, r#"{"alpha":true,"nested":["a\"b\\c\n",-5],"zebra":1}"#);
        // Determinism.
        assert_eq!(canonical_json(&value), json);
        // Round-trip through serde_json into the same canonical form.
        let parsed: CanonicalValue = serde_json::from_str(&json).unwrap();
        assert_eq!(canonical_json(&parsed), json);
        // Unicode escapes for control characters.
        let ctrl = CanonicalValue::Str("\u{01}".to_owned());
        assert_eq!(canonical_json(&ctrl), "\"\\u0001\"");
    }

    #[test]
    fn url_policy_is_enforced() {
        assert!(validate_webhook_url("https://example.com/hook", EnvironmentKind::Prod).is_ok());
        assert!(validate_webhook_url("https://example.com", EnvironmentKind::Dev).is_ok());
        assert!(validate_webhook_url("https://example.com:8443/hook?x=1", EnvironmentKind::Prod).is_ok());
        assert!(validate_webhook_url("http://localhost:9999/hook", EnvironmentKind::Dev).is_ok());
        assert!(validate_webhook_url("http://localhost:9999/hook", EnvironmentKind::Staging).is_ok());
        assert!(matches!(
            validate_webhook_url("http://localhost/hook", EnvironmentKind::Prod),
            Err(WebhookError::InvalidUrl(_))
        ));
        for bad in [
            "ftp://example.com/hook",
            "example.com/hook",
            "https:///hook",
            "https://user:pass@example.com/hook",
            "https://example.com/hook#frag",
            "https://exa mple.com/hook",
            "https://example.com/\u{7}",
        ] {
            assert!(
                matches!(validate_webhook_url(bad, EnvironmentKind::Dev), Err(WebhookError::InvalidUrl(_))),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn secret_validation_and_redaction() {
        assert!(WebhookSecret::new(vec![0u8; 15]).is_err());
        assert!(WebhookSecret::new(vec![0u8; 16]).is_ok());
        assert!(WebhookSecret::new(vec![0u8; 256]).is_ok());
        assert!(WebhookSecret::new(vec![0u8; 257]).is_err());
        let secret = WebhookSecret::new(vec![0xabu8; 32]).unwrap();
        assert!(format!("{secret:?}").contains("redacted"));
        // serde round-trip keeps the secret material (hex).
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let back: WebhookSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 32);
    }

    #[test]
    fn registration_validation() {
        let (apps, mut store, app, env) = setup();
        // Empty event set rejected.
        assert_eq!(
            store
                .register(&apps, &app, &env, "https://example.com/h", BTreeSet::new(),
                    WebhookSecret::new(vec![7u8; 32]).unwrap(), 1)
                .unwrap_err(),
            WebhookError::NoEventTypes
        );
        // http rejected in prod.
        assert!(matches!(
            store
                .register(&apps, &app, &env, "http://localhost/h", [EventType::PointsChanged].into(),
                    WebhookSecret::new(vec![7u8; 32]).unwrap(), 1)
                .unwrap_err(),
            WebhookError::InvalidUrl(_)
        ));
        let reg = register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::PointsChanged, EventType::ConnectionChanged], "0123456789abcdef");
        assert!(reg.is_active());
        assert_eq!(reg.event_types.len(), 2);
        assert!(reg.subscribes(EventType::PointsChanged));
        assert!(!reg.subscribes(EventType::GatewayChanged));
    }

    #[test]
    fn emit_signs_with_each_registration_secret_and_creates_deliveries() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://one.example/h",
            &[EventType::ConnectionChanged], "secret-one-16bytes");
        register(&mut store, &apps, &app, &env, "https://two.example/h",
            &[EventType::ConnectionChanged, EventType::PointsChanged], "secret-two-16bytes");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 2_000)
            .unwrap();
        assert_eq!(emitted.len(), 2);
        for e in &emitted {
            assert_eq!(e.signed_event.scheme, WEBHOOK_SIGNATURE_SCHEME);
            assert_eq!(e.signed_event.occurred_at, 2_000);
            // The signature verifies under the registration's own secret.
            let reg = store.registration(&e.signed_event.webhook_id).unwrap();
            let expected = sign_event_bytes(&reg.secret, &e.signed_event.canonical_bytes());
            assert_eq!(expected, e.signed_event.signature);
            assert!(matches!(
                store.delivery(&e.delivery_id).unwrap().state,
                DeliveryState::Pending
            ));
        }
        // Different secrets ⇒ different signatures (per-webhook keys).
        assert_ne!(emitted[0].signed_event.signature, emitted[1].signed_event.signature);
        // Unsubscribed event type emits nothing (not an error).
        let none = store
            .emit_event(&apps, &app, &env, EventType::GatewayChanged, payload(), 2_001)
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn verify_happy_path_then_replay_rejected() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "verify-secret-16byt");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 2_000)
            .unwrap();
        let signed = emitted[0].signed_event.clone();
        store.verify_event(&apps, &app, &signed, 2_100).unwrap();
        // Replay: same event id ⇒ rejected.
        assert_eq!(
            store.verify_event(&apps, &app, &signed, 2_101),
            Err(WebhookError::EventReplayed)
        );
    }

    #[test]
    fn timestamp_window_enforced_both_directions() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "window-secret-16byt");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 2_000)
            .unwrap();
        let signed = emitted[0].signed_event.clone();
        // Exactly at tolerance (±300): inside.
        assert!(store.verify_event(&apps, &app, &signed, 2_300).is_ok());
        let emitted2 = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 2_000)
            .unwrap();
        let signed2 = emitted2[0].signed_event.clone();
        // One second too old: outside.
        assert!(matches!(
            store.verify_event(&apps, &app, &signed2, 2_301),
            Err(WebhookError::TimestampOutOfWindow { .. })
        ));
        // From the future: outside.
        let emitted3 = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 5_000)
            .unwrap();
        let signed3 = emitted3[0].signed_event.clone();
        assert!(matches!(
            store.verify_event(&apps, &app, &signed3, 2_000),
            Err(WebhookError::TimestampOutOfWindow { .. })
        ));
    }

    #[test]
    fn delivery_state_machine_transitions() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "delivery-secret-16b");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 1_000)
            .unwrap();
        let delivery = emitted[0].delivery_id.clone();
        assert!(store.pending_due(1_000).contains(&delivery));
        // First failure: attempts=1, backoff 60s.
        store
            .record_outcome(&delivery, DeliveryOutcome::AttemptFailed { reason: "timeout".into() }, 1_010)
            .unwrap();
        let record = store.delivery(&delivery).unwrap();
        assert_eq!(record.attempts(), 1);
        assert!(!record.is_due(1_020));
        assert!(record.is_due(1_070));
        // Deliver on retry.
        let delivered = store
            .record_outcome(&delivery, DeliveryOutcome::Delivered { http_status: 200 }, 1_070)
            .unwrap();
        assert!(matches!(delivered.state, DeliveryState::Delivered { http_status: 200, .. }));
        assert!(store.pending_due(2_000).is_empty());
        // Terminal state: no further transitions.
        assert!(matches!(
            store.record_outcome(&delivery, DeliveryOutcome::Delivered { http_status: 200 }, 1_080),
            Err(WebhookError::InvalidTransition(_))
        ));
    }

    #[test]
    fn delivery_expires_after_max_attempts() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "expire-secret-16byt");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 1_000)
            .unwrap();
        let delivery = emitted[0].delivery_id.clone();
        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            let record = store
                .record_outcome(&delivery, DeliveryOutcome::AttemptFailed { reason: format!("err{attempt}") }, 1_000 + attempt as u64)
                .unwrap();
            if attempt < MAX_DELIVERY_ATTEMPTS {
                assert_eq!(record.attempts(), attempt);
            } else {
                assert!(matches!(record.state, DeliveryState::Expired { .. }));
            }
        }
        // Further failure on Expired: invalid transition.
        assert!(matches!(
            store.record_outcome(&delivery, DeliveryOutcome::AttemptFailed { reason: "x".into() }, 9_999),
            Err(WebhookError::InvalidTransition(_))
        ));
    }

    #[test]
    fn backoff_is_bounded_and_deterministic() {
        assert_eq!(DeliveryState::backoff_secs(1), 60);
        assert_eq!(DeliveryState::backoff_secs(2), 120);
        assert_eq!(DeliveryState::backoff_secs(3), 240);
        assert_eq!(DeliveryState::backoff_secs(7), 3600);
        assert_eq!(DeliveryState::backoff_secs(60), 3600);
    }

    #[test]
    fn signed_event_serde_round_trip_is_hex_canonical() {
        let (apps, mut store, app, env) = setup();
        register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "serde-secret-16bytes");
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 1_234)
            .unwrap();
        let signed = &emitted[0].signed_event;
        let json = serde_json::to_string(signed).unwrap();
        assert!(json.contains("\"scheme\":\"sharenet-webhook-hmacsha256-v1\""));
        assert!(json.contains("\"event_type\":\"connection_changed\""));
        let back: SignedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *signed);
        assert_eq!(back.canonical_bytes(), signed.canonical_bytes());
    }

    #[test]
    fn revoked_registration_stops_emission_and_verification() {
        let (apps, mut store, app, env) = setup();
        let reg = register(&mut store, &apps, &app, &env, "https://example.com/h",
            &[EventType::ConnectionChanged], "revoked-secret-16b");
        // Emit while active.
        let emitted = store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 1_100)
            .unwrap();
        assert_eq!(emitted.len(), 1);
        let signed = emitted[0].signed_event.clone();
        store.revoke(&reg.webhook_id, "rotated url", 1_200).unwrap();
        // No emission to a revoked registration.
        assert!(store
            .emit_event(&apps, &app, &env, EventType::ConnectionChanged, payload(), 1_300)
            .unwrap()
            .is_empty());
        // Verification of an event signed BEFORE revocation fails closed
        // (with a perfectly valid signature).
        assert!(matches!(
            store.verify_event(&apps, &app, &signed, 1_300),
            Err(WebhookError::WebhookRevoked(_))
        ));
    }

    #[test]
    fn app_scoped_lookups_never_leak_other_apps() {
        let (mut apps, mut store, _, _) = setup();
        let app_a = apps.create_app("a", &[AppProfile::Consumer], 1).unwrap().app_id.clone();
        let env_a = apps.create_environment(&app_a, EnvironmentKind::Prod, 2).unwrap().environment_id.clone();
        let app_b = apps.create_app("b", &[AppProfile::Consumer], 3).unwrap().app_id.clone();
        let env_b = apps.create_environment(&app_b, EnvironmentKind::Prod, 4).unwrap().environment_id.clone();
        let reg_a = register(&mut store, &apps, &app_a, &env_a, "https://a.example/h",
            &[EventType::PointsChanged], "app-a-secret-16byte");
        let reg_b = register(&mut store, &apps, &app_b, &env_b, "https://b.example/h",
            &[EventType::PointsChanged], "app-b-secret-16byte");
        // App A's list contains only A's registrations.
        let a_list = store.registrations_for_app(&app_a);
        assert_eq!(a_list.len(), 1);
        assert_eq!(a_list[0].webhook_id, reg_a.webhook_id);
        // App A cannot look up app B's webhook: unknown (no oracle).
        assert!(store.registration_for_app(&app_a, &reg_b.webhook_id).is_none());
        assert!(store.registration_for_app(&app_b, &reg_a.webhook_id).is_none());
        assert!(store.registration(&reg_b.webhook_id).is_some(), "audit path exists");
        // Events emitted for A verify under A; the same signed event under
        // B's app context is unknown.
        let emitted = store
            .emit_event(&apps, &app_a, &env_a, EventType::PointsChanged, payload(), 10)
            .unwrap();
        assert_eq!(emitted.len(), 1);
        let signed = emitted[0].signed_event.clone();
        assert!(store.verify_event(&apps, &app_a, &signed, 20).is_ok());
        assert!(matches!(
            store.verify_event(&apps, &app_b, &signed, 20),
            Err(WebhookError::UnknownWebhook(_))
        ));
        // Emission for A never delivers to B's webhook.
        let b_before = store.deliveries_for_app(&app_b).len();
        store.emit_event(&apps, &app_a, &env_a, EventType::PointsChanged, payload(), 30).unwrap();
        assert_eq!(store.deliveries_for_app(&app_b).len(), b_before);
    }
}
