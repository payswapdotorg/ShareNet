//! The typed wire-client error — same discipline as the parent crate's
//! `PortError` (stable machine names, no panic paths, no strings-as-errors;
//! strings appear only as *evidence* of unknown vocabulary a broken or
//! foreign server sent, never as error codes).
//!
//! [`AdcosError`] is the full typed surface of the adapter: everything that
//! can go wrong between a [`crate::AdcosClient`] call and the ADCOS
//! developer API. The `ConnectivityPort` trait only speaks
//! `sharenet_connectivity::PortError`, so the trait impl flattens
//! [`AdcosError`] through [`crate::AdcosClient`] context (see
//! `client.rs`): typed provider refusals pass through unchanged
//! ([`AdcosError::Port`]), and every transport/protocol failure degrades to
//! `PortError::ProviderUnavailable` carrying the client-side
//! cached-observation freshness bound — because when the provider cannot
//! deliver a trustworthy answer, the boundary laws ("do not fabricate a
//! contract state; cache the last accepted observation with freshness
//! metadata") are exactly what the caller must fall back to.

use core::fmt;

use sharenet_connectivity::PortError;
use sharenet_protocol::ConnectivityEvidenceError;

/// Why a response body (or a codec artifact) could not be turned into the
/// domain types — the typed "malformed response" family.
///
/// Strings appear only where the offending *evidence* is itself an
/// unpredictable token from the server (an unknown observation kind, an
/// unknown error code): they are diagnostic evidence, not machine names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedReason {
    /// The HTTP status line was not `HTTP/1.x <3 digits>[ reason]`.
    BadStatusLine,
    /// The request line was not `<METHOD> <path> HTTP/1.1`.
    BadRequestLine,
    /// A header line had no `name: value` shape, or the head was not UTF-8.
    BadHeaderLine,
    /// The response head exceeded the read cap.
    HeadersTooLarge { len: usize, max: usize },
    /// Two `Content-Length` headers disagreed.
    DuplicateContentLength,
    /// `Content-Length` was not a parsable non-negative number.
    ContentLengthInvalid,
    /// A full-message parse found no `\r\n\r\n` head terminator.
    HeadIncomplete,
    /// `Transfer-Encoding` is present — this client speaks the strict
    /// Content-Length subset only (documented simplification).
    ChunkedUnsupported,
    /// A declared body exceeded the read cap.
    BodyTooLarge { len: usize, max: usize },
    /// The bytes after the head did not match `Content-Length`.
    BodyLengthMismatch { expected: usize, found: usize },
    /// A request carried a method outside {GET, POST}.
    BadMethod,
    /// The body was not the JSON the endpoint's success shape requires.
    BadJson,
    /// A required field of the success shape was absent.
    MissingField(&'static str),
    /// A reference id was not exactly 64 lowercase hex characters.
    BadRefId,
    /// A reference `kind` string outside the frozen {intent, offer, contract} set.
    UnknownRefKind(String),
    /// An observation `kind` outside the six adcos.md event names.
    UnknownObservationKind(String),
    /// A contract `state` outside {projected, active, degraded, terminated}.
    UnknownContractState(String),
    /// A service class outside the frozen ADR-003 set.
    UnknownServiceClass(String),
    /// An error-envelope `code` outside the PortError machine-name table.
    UnknownErrorCode(String),
    /// The error-envelope code arrived with an HTTP status outside its
    /// documented pairing.
    CodeStatusMismatch { code: String, status: u16 },
    /// Encoding one of our own request DTOs failed (should be impossible;
    /// typed instead of a panic).
    EncodeFailed,
    /// An assurance element carried no `signed_envelope` — an UNSIGNED
    /// observation (the pre-R5-004 shape). Unsigned observations never
    /// enter the connectivity layer (the R5-004 registry rule), so this is
    /// a typed refusal, never a silent fall-back to the unsigned fields.
    UnsignedObservation,
    /// The `signed_envelope` field was not lowercase hex.
    SignedEnvelopeNotHex,
    /// The JSON observation fields disagree with the SIGNED statement
    /// inside the envelope (an envelope/JSON mismatch — e.g. a proxy or
    /// provider rewriting the JSON wrapper). The observation is refused;
    /// the signed bytes are the truth, the wrapper is not.
    ObservationDisagreement { field: &'static str },
}

/// Everything that can go wrong on the wire side of the ADCOS boundary.
///
/// Transport classes carry `attempts` — how many connection attempts were
/// consumed before giving up (bounded by the configured `max_attempts`;
/// POST requests are never replayed after their bytes were sent, so a
/// mid-call drop stops at `attempts: 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdcosError {
    /// Connecting to the ADCOS endpoint failed (non-timeout) on every attempt.
    ConnectFailed { attempts: u32 },
    /// Connecting timed out on every attempt.
    ConnectTimedOut { attempts: u32 },
    /// A connected call timed out (read/write) on every attempt.
    TimedOut { attempts: u32 },
    /// The connection was closed before a complete response arrived.
    ConnectionDropped { attempts: u32 },
    /// The HTTP status is outside the documented set for this wire shape.
    HttpStatus { status: u16 },
    /// The response could not be decoded into the domain types.
    Malformed { reason: MalformedReason },
    /// A typed provider refusal — already a [`PortError`] (machine-named),
    /// carried through untouched.
    Port(PortError),
    /// A signed connectivity observation (R5-004) failed the protocol
    /// core's verification or admission — the typed
    /// [`ConnectivityEvidenceError`] with its stable machine name
    /// (`signature_invalid`, `contract_unknown`, `expired`, ...). Through
    /// the trait this degrades to `ProviderUnavailable`: an answer that
    /// fails verification is not a trustworthy answer.
    Evidence(ConnectivityEvidenceError),
    /// The client configuration is invalid (zero timeout, zero attempts...).
    ConfigInvalid { what: &'static str },
}

impl AdcosError {
    /// Stable machine name (the parent crate's `PortError::name`
    /// discipline).
    pub fn name(&self) -> &'static str {
        match self {
            AdcosError::ConnectFailed { .. } => "connect_failed",
            AdcosError::ConnectTimedOut { .. } => "connect_timed_out",
            AdcosError::TimedOut { .. } => "timed_out",
            AdcosError::ConnectionDropped { .. } => "connection_dropped",
            AdcosError::HttpStatus { .. } => "http_status",
            AdcosError::Malformed { .. } => "malformed_response",
            AdcosError::Port(_) => "port_error",
            AdcosError::Evidence(_) => "evidence_invalid",
            AdcosError::ConfigInvalid { .. } => "config_invalid",
        }
    }

    /// Whether this is a transport-level failure (connection could not be
    /// established or maintained) — the family the trait impl degrades to
    /// `PortError::ProviderUnavailable`.
    pub fn is_transport(&self) -> bool {
        matches!(
            self,
            AdcosError::ConnectFailed { .. }
                | AdcosError::ConnectTimedOut { .. }
                | AdcosError::TimedOut { .. }
                | AdcosError::ConnectionDropped { .. }
        )
    }
}

impl From<PortError> for AdcosError {
    fn from(error: PortError) -> Self {
        AdcosError::Port(error)
    }
}

impl fmt::Display for AdcosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdcosError::ConnectFailed { attempts } => {
                write!(f, "connecting to ADCOS failed after {attempts} attempt(s)")
            }
            AdcosError::ConnectTimedOut { attempts } => {
                write!(f, "connecting to ADCOS timed out after {attempts} attempt(s)")
            }
            AdcosError::TimedOut { attempts } => {
                write!(f, "ADCOS call timed out after {attempts} attempt(s)")
            }
            AdcosError::ConnectionDropped { attempts } => write!(
                f,
                "ADCOS connection dropped before a complete response ({attempts} attempt(s) consumed)"
            ),
            AdcosError::HttpStatus { status } => {
                write!(f, "ADCOS returned HTTP status {status}, outside this wire shape's documented set")
            }
            AdcosError::Malformed { reason } => {
                write!(f, "malformed ADCOS response: {reason:?}")
            }
            AdcosError::Port(error) => write!(f, "ADCOS refused the call: {error}"),
            AdcosError::Evidence(error) => {
                write!(f, "connectivity observation failed verification: {error}")
            }
            AdcosError::ConfigInvalid { what } => {
                write!(f, "invalid client configuration: {what}")
            }
        }
    }
}

impl std::error::Error for AdcosError {}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_connectivity::RefKind;

    #[test]
    fn machine_names_are_stable() {
        let errors = [
            AdcosError::ConnectFailed { attempts: 2 },
            AdcosError::ConnectTimedOut { attempts: 1 },
            AdcosError::TimedOut { attempts: 3 },
            AdcosError::ConnectionDropped { attempts: 1 },
            AdcosError::HttpStatus { status: 418 },
            AdcosError::Malformed {
                reason: MalformedReason::BadJson,
            },
            AdcosError::Port(PortError::AcquisitionUnauthorized),
            AdcosError::Evidence(ConnectivityEvidenceError::SignatureInvalid),
            AdcosError::ConfigInvalid { what: "max_attempts" },
        ];
        let names: Vec<&str> = errors.iter().map(|e| e.name()).collect();
        assert_eq!(
            names,
            [
                "connect_failed",
                "connect_timed_out",
                "timed_out",
                "connection_dropped",
                "http_status",
                "malformed_response",
                "port_error",
                "evidence_invalid",
                "config_invalid",
            ]
        );
        for error in &errors {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn transport_classification_is_exact() {
        let transport = [
            AdcosError::ConnectFailed { attempts: 1 },
            AdcosError::ConnectTimedOut { attempts: 1 },
            AdcosError::TimedOut { attempts: 2 },
            AdcosError::ConnectionDropped { attempts: 3 },
        ];
        for error in &transport {
            assert!(error.is_transport(), "{error:?}");
        }
        let not_transport = [
            AdcosError::HttpStatus { status: 500 },
            AdcosError::Malformed {
                reason: MalformedReason::BadStatusLine,
            },
            AdcosError::Port(PortError::ContractUnknown {
                contract: sharenet_connectivity::ConnectivityContractRef::from_id([0; 32]),
            }),
            // A verification failure is not a transport failure: the
            // provider answered; the answer failed verification.
            AdcosError::Evidence(ConnectivityEvidenceError::SignatureInvalid),
        ];
        for error in &not_transport {
            assert!(!error.is_transport(), "{error:?}");
        }
    }

    #[test]
    fn port_errors_wrap_and_display() {
        let wrapped: AdcosError = PortError::RefKindMismatch {
            expected: RefKind::Contract,
            found: RefKind::Offer,
        }
        .into();
        assert_eq!(wrapped.name(), "port_error");
        assert!(wrapped.to_string().contains("reference kind mismatch"));
        let inner = match wrapped {
            AdcosError::Port(p) => p,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(inner.name(), "ref_kind_mismatch");
    }
}
