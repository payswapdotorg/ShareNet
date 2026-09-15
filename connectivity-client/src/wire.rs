//! The ADCOS developer-API wire shape — THIS crate's documented mapping of
//! the `ConnectivityPort` trait onto JSON-over-HTTP endpoints.
//!
//! `spec/integrations/adcos.md` says: *"The actual wire client speaks the
//! ADCOS developer API. The domain does not import ADCOS server
//! internals."* and *"Only the ADCOS adapter may know the ADCOS developer
//! API transport format."* This module (plus `http.rs` and `transport.rs`)
//! IS that adapter knowledge — the only place in ShareNet that knows what
//! an ADCOS request or response looks like on the wire.
//!
//! # Endpoint table (the adapter's documented mapping)
//!
//! | Trait method | HTTP | Path | Success body |
//! |---|---|---|---|
//! | `create_intent` | POST | `/intents` | `{"intent_ref":WireRef}` |
//! | `discover_offers` | GET | `/intents/{id}/offers` | `[WireRef]` |
//! | `accept_offer` | POST | `/intents/{id}/offers/{offer}/accept` | `{"contract_ref":WireRef}` |
//! | `get_contract` | GET | `/contracts/{id}` | projection fields |
//! | `get_assurance` | GET | `/contracts/{id}/assurance` | `[observation fields + signed_envelope]` |
//! | `get_execution` | GET | `/contracts/{id}/execution` | execution fields |
//! | `terminate` | POST | `/contracts/{id}/terminate` | `{}` |
//!
//! `{id}` path segments are the 64 lowercase hex characters of the 32-byte
//! opaque reference id. A `WireRef` is `{"kind":"intent|offer|contract",
//! "id":"<64 lowercase hex>"}` — the kind tag rides along so a wrong-kind
//! reference is a typed `PortError::RefKindMismatch` (the parent's
//! `from_parts` seam), never a silent re-type.
//!
//! # Error envelope
//!
//! Every failure status carries `{"error":{"code":"<PortError machine
//! name>", ...typed fields}}` — the parent crate's stable machine names are
//! the wire error vocabulary (that is exactly what they were designed
//! for). The code↔status pairing is part of this contract and is validated
//! by the client; a mismatch is a typed `MalformedReason::CodeStatusMismatch`.
//!
//! | code | HTTP | typed fields |
//! |---|---|---|
//! | `requirement_version_unsupported` | 400 | `found` |
//! | `region_hint_too_long` | 400 | `len`, `max` |
//! | `acquisition_unauthorized` | 401 | — |
//! | `intent_unknown` | 404 | `intent` |
//! | `offer_unknown` | 404 | `offer` |
//! | `contract_unknown` | 404 | `contract` |
//! | `offer_not_for_intent` | 409 | `offer`, `passed_intent` |
//! | `offer_already_consumed` | 409 | `offer`, `contract` |
//! | `contract_terminated` | 409 | `contract` |
//! | `validity_window_invalid` | 422 | `valid_from_unix`, `valid_until_unix` |
//! | `execution_state_text_too_long` | 422 | `len`, `max` |
//! | `ref_kind_mismatch` | 422 | `expected_kind`, `found_kind` |
//! | `provider_unavailable` | 503 | `last_observation_fresh_until_unix` (optional) |
//!
//! Everything here is pure data — no sockets — so it compiles everywhere
//! the parent crate does, including `wasm32-unknown-unknown`.

use serde::{Deserialize, Serialize};

use sharenet_connectivity::{
    ConnectivityContractProjection, ConnectivityContractRef, ConnectivityExecutionProjection,
    ConnectivityIntentRef, ConnectivityObservation, ConnectivityOfferRef, ConnectivityRequirement,
    ObservationKind, PortError, RefKind, REF_ID_LEN,
};
use sharenet_protocol::{
    ConnectivityObservationStatement, ObservationAdmission, SignedConnectivityObservation,
};

use crate::error::{AdcosError, MalformedReason};
use crate::hex::{decode_lower_hex, decode_lower_hex_32, encode_lower_hex};
use crate::http::{HttpRequest, Method};

// ---------------------------------------------------------------------------
// References
// ---------------------------------------------------------------------------

/// An opaque reference on the wire: the kind tag plus the 64 lowercase hex
/// characters of the 32-byte id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRef {
    /// One of `intent` / `offer` / `contract`.
    pub kind: String,
    /// Exactly 64 lowercase hex characters.
    pub id: String,
}

/// Encode a reference for the wire (kind tag + lowercase hex id).
pub fn ref_to_wire(kind: RefKind, id: &[u8; REF_ID_LEN]) -> WireRef {
    WireRef {
        kind: kind.as_str().to_string(),
        id: encode_lower_hex(id),
    }
}

/// The kind a wire ref must carry to be decoded as a given type — strict:
/// anything else (unknown or known-but-wrong) is a malformed envelope for
/// error-field refs, and a typed `RefKindMismatch` for success-shape refs.
fn wire_id(wire: &WireRef) -> Result<[u8; REF_ID_LEN], AdcosError> {
    decode_lower_hex_32(&wire.id).map_err(|reason| AdcosError::Malformed { reason })
}

/// Decode an intent reference (success shapes: the ref the endpoint
/// returned is context-checked by `from_parts`).
pub fn parse_intent_ref(wire: &WireRef) -> Result<ConnectivityIntentRef, AdcosError> {
    ConnectivityIntentRef::from_parts(kind_of(wire)?, wire_id(wire)?).map_err(AdcosError::Port)
}

/// Decode an offer reference.
pub fn parse_offer_ref(wire: &WireRef) -> Result<ConnectivityOfferRef, AdcosError> {
    ConnectivityOfferRef::from_parts(kind_of(wire)?, wire_id(wire)?).map_err(AdcosError::Port)
}

/// Decode a contract reference.
pub fn parse_contract_ref(wire: &WireRef) -> Result<ConnectivityContractRef, AdcosError> {
    ConnectivityContractRef::from_parts(kind_of(wire)?, wire_id(wire)?).map_err(AdcosError::Port)
}

fn kind_of(wire: &WireRef) -> Result<RefKind, AdcosError> {
    RefKind::from_name(&wire.kind).ok_or(AdcosError::Malformed {
        reason: MalformedReason::UnknownRefKind(wire.kind.clone()),
    })
}

// ---------------------------------------------------------------------------
// Request builders (the endpoint table as code)
// ---------------------------------------------------------------------------

/// `POST /intents` body — the requirement fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateIntentBody {
    /// The requirement struct version.
    pub version: u32,
    /// Frozen ADR-003 service class machine name.
    pub service_class: String,
    /// Optional max-cost hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost_hint: Option<u64>,
    /// Optional max-latency hint (milliseconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_latency_ms_hint: Option<u64>,
    /// Optional region hint text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_hint: Option<String>,
}

/// The empty JSON object body the accept and terminate POSTs carry.
pub const EMPTY_JSON_BODY: &[u8] = b"{}";

/// Encode a requirement as the `POST /intents` body.
pub fn requirement_body(requirement: &ConnectivityRequirement) -> Result<Vec<u8>, AdcosError> {
    let body = CreateIntentBody {
        version: requirement.version,
        service_class: requirement.service_class.as_str().to_string(),
        max_cost_hint: requirement.max_cost_hint,
        max_latency_ms_hint: requirement.max_latency_ms_hint,
        region_hint: requirement.region_hint.clone(),
    };
    encode(&body)
}

/// `POST /intents` request.
pub fn intents_request(requirement: &ConnectivityRequirement) -> Result<HttpRequest, AdcosError> {
    Ok(HttpRequest {
        method: Method::Post,
        path: "/intents".to_string(),
        body: requirement_body(requirement)?,
    })
}

/// `GET /intents/{id}/offers` request.
pub fn offers_request(intent: &ConnectivityIntentRef) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        path: format!("/intents/{}/offers", encode_lower_hex(intent.id())),
        body: Vec::new(),
    }
}

/// `POST /intents/{id}/offers/{offer}/accept` request.
pub fn accept_request(intent: &ConnectivityIntentRef, offer: &ConnectivityOfferRef) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        path: format!(
            "/intents/{}/offers/{}/accept",
            encode_lower_hex(intent.id()),
            encode_lower_hex(offer.id())
        ),
        body: EMPTY_JSON_BODY.to_vec(),
    }
}

/// `GET /contracts/{id}` request.
pub fn contract_request(contract: &ConnectivityContractRef) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        path: format!("/contracts/{}", encode_lower_hex(contract.id())),
        body: Vec::new(),
    }
}

/// `GET /contracts/{id}/assurance` request.
pub fn assurance_request(contract: &ConnectivityContractRef) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        path: format!("/contracts/{}/assurance", encode_lower_hex(contract.id())),
        body: Vec::new(),
    }
}

/// `GET /contracts/{id}/execution` request.
pub fn execution_request(contract: &ConnectivityContractRef) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        path: format!("/contracts/{}/execution", encode_lower_hex(contract.id())),
        body: Vec::new(),
    }
}

/// `POST /contracts/{id}/terminate` request.
pub fn terminate_request(contract: &ConnectivityContractRef) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        path: format!("/contracts/{}/terminate", encode_lower_hex(contract.id())),
        body: EMPTY_JSON_BODY.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Response DTOs + parsers (the endpoint table as code)
// ---------------------------------------------------------------------------

/// `{"intent_ref": WireRef}` — `POST /intents` success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRefBody {
    /// The created intent reference.
    pub intent_ref: WireRef,
}

/// `{"contract_ref": WireRef}` — the accept success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRefBody {
    /// The created contract reference.
    pub contract_ref: WireRef,
}

/// `GET /contracts/{id}` success body — the projection fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionBody {
    /// The contract this projection reports.
    pub contract_ref: WireRef,
    /// `projected` / `active` / `degraded` / `terminated`.
    pub state: String,
    /// Validity window start (unix seconds).
    pub valid_from_unix: u64,
    /// Validity window end (unix seconds).
    pub valid_until_unix: u64,
    /// Freshness timestamp (unix seconds).
    pub freshness_unix: u64,
}

/// One `GET /contracts/{id}/assurance` element — the observation fields.
///
/// The R5-004 trust rule: the JSON fields are a WRAPPER, never the truth.
/// The truth is [`SignedConnectivityObservation`] inside `signed_envelope`
/// (lowercase hex of the canonical CBOR carrying envelope), signed with the
/// provider's ShareNet node key. A missing envelope is the unsigned
/// pre-R5-004 shape and is refused by [`verify_observation_dtos`]; a
/// disagreeing wrapper is refused too (the signed bytes win).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBody {
    /// One of the six adcos.md event machine names.
    pub kind: String,
    /// When the provider observed it (unix seconds).
    pub observed_at_unix: u64,
    /// The contract the observation belongs to.
    pub contract: WireRef,
    /// Monotonic per-provider sequence number.
    pub sequence: u64,
    /// Lowercase hex of the SignedConnectivityObservation carrying
    /// envelope (R5-004). `None` on the unsigned pre-R5-004 shape — kept
    /// optional so the JSON still parses and the refusal is TYPED
    /// ([`MalformedReason::UnsignedObservation`]), not a `BadJson` blur.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signed_envelope: Option<String>,
}

/// `GET /contracts/{id}/execution` success body — the execution fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBody {
    /// The contract this execution belongs to.
    pub contract_ref: WireRef,
    /// Provider execution state text (bounded).
    pub state: String,
    /// Throughput in bits/second.
    pub throughput_bps: u64,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// Freshness timestamp (unix seconds).
    pub freshness_unix: u64,
}

fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, AdcosError> {
    serde_json::from_slice(body)
        .map_err(|_| AdcosError::Malformed { reason: MalformedReason::BadJson })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AdcosError> {
    serde_json::to_vec(value).map_err(|_| AdcosError::Malformed { reason: MalformedReason::EncodeFailed })
}

/// Parse the `POST /intents` success body.
pub fn parse_intent_ref_body(body: &[u8]) -> Result<ConnectivityIntentRef, AdcosError> {
    let parsed: IntentRefBody = decode(body)?;
    parse_intent_ref(&parsed.intent_ref)
}

/// Parse the `GET /intents/{id}/offers` success body.
pub fn parse_offer_refs_body(body: &[u8]) -> Result<Vec<ConnectivityOfferRef>, AdcosError> {
    let parsed: Vec<WireRef> = decode(body)?;
    parsed.iter().map(parse_offer_ref).collect()
}

/// Parse the accept success body.
pub fn parse_contract_ref_body(body: &[u8]) -> Result<ConnectivityContractRef, AdcosError> {
    let parsed: ContractRefBody = decode(body)?;
    parse_contract_ref(&parsed.contract_ref)
}

/// Parse the `GET /contracts/{id}` success body into the parent's read-only
/// projection (validity window enforced at construction — a provider
/// sending an inverted window gets the typed `PortError::ValidityWindowInvalid`,
/// never a fabricated projection).
pub fn parse_projection_body(body: &[u8]) -> Result<ConnectivityContractProjection, AdcosError> {
    let parsed: ProjectionBody = decode(body)?;
    let contract = parse_contract_ref(&parsed.contract_ref)?;
    let state = contract_state_from_name(&parsed.state)?;
    ConnectivityContractProjection::new(
        contract,
        state,
        parsed.valid_from_unix,
        parsed.valid_until_unix,
        parsed.freshness_unix,
    )
    .map_err(AdcosError::Port)
}

/// Parse the `GET /contracts/{id}/assurance` success body into the raw
/// observation DTOs (kind vocabulary + contract refs validated; the signed
/// envelopes are NOT verified here — that is
/// [`verify_observation_dtos`], the R5-004 trust boundary).
pub fn parse_observation_dtos(body: &[u8]) -> Result<Vec<ObservationBody>, AdcosError> {
    let parsed: Vec<ObservationBody> = decode(body)?;
    for obs in &parsed {
        if ObservationKind::from_name(&obs.kind).is_none() {
            return Err(AdcosError::Malformed {
                reason: MalformedReason::UnknownObservationKind(obs.kind.clone()),
            });
        }
        parse_contract_ref(&obs.contract)?;
    }
    Ok(parsed)
}

/// The R5-004 trust boundary as one function: every observation on the
/// assurance body is turned into domain data ONLY after the strict
/// envelope parse, the strict statement parse, the DTO/statement agreement
/// check and the full protocol-core admission (Ed25519 signature against
/// the embedded provider identity, the known-contract rule, the
/// per-(provider node_id, contract_ref) monotonic sequence gate and the
/// accepting node's freshness window). Unsigned, tampered, disagreeing or
/// unknown-contract observations fail with typed errors and NOTHING is
/// returned — there is no partial-success path into the domain.
///
/// `AdmissionOutcome::SequenceStale` entries (verified redeliveries the
/// sequence gate already covers) are still returned: they are verified
/// observations, and redelivery dedup is the CONSUMER's policy (the
/// R5-003 store's `accept` and the client cache both dedup by sequence).
pub fn verify_observation_dtos(
    dtos: &[ObservationBody],
    admission: &mut ObservationAdmission,
    now_unix: u64,
) -> Result<Vec<ConnectivityObservation>, AdcosError> {
    let mut verified = Vec::with_capacity(dtos.len());
    for dto in dtos {
        let Some(envelope_hex) = dto.signed_envelope.as_deref() else {
            return Err(AdcosError::Malformed {
                reason: MalformedReason::UnsignedObservation,
            });
        };
        let envelope_bytes = decode_lower_hex(envelope_hex).map_err(|_| AdcosError::Malformed {
            reason: MalformedReason::SignedEnvelopeNotHex,
        })?;
        let signed =
            SignedConnectivityObservation::from_envelope_bytes(&envelope_bytes)
                .map_err(AdcosError::Evidence)?;
        // strict parse of the signed bytes (the R1-001 node_id derivation of
        // the provider identity happens inside the identity parse)
        let statement = signed.observation().map_err(AdcosError::Evidence)?;
        // the JSON wrapper must agree with the signed statement — the
        // signed bytes are the truth, the wrapper is not
        check_agreement(dto, &statement)?;
        // the full protocol-core admission (signature, known contract,
        // sequence gate, freshness — in the registry's order)
        admission.receive(&signed, now_unix).map_err(AdcosError::Evidence)?;
        // only now does the observation enter the connectivity domain, and
        // its fields come from the SIGNED statement
        let kind = ObservationKind::from_name(statement.kind().as_str())
            .expect("agreement check proved the kind name is in the frozen six");
        let contract =
            ConnectivityContractRef::from_parts(RefKind::Contract, *statement.contract_ref())
                .map_err(AdcosError::Port)?;
        verified.push(ConnectivityObservation::new(
            kind,
            statement.observed_at_unix(),
            contract,
            statement.sequence(),
        ));
    }
    Ok(verified)
}

/// The JSON wrapper must agree with the signed statement field-for-field.
fn check_agreement(
    dto: &ObservationBody,
    statement: &ConnectivityObservationStatement,
) -> Result<(), AdcosError> {
    if dto.kind != statement.kind().as_str() {
        return Err(AdcosError::Malformed {
            reason: MalformedReason::ObservationDisagreement { field: "kind" },
        });
    }
    if dto.observed_at_unix != statement.observed_at_unix() {
        return Err(AdcosError::Malformed {
            reason: MalformedReason::ObservationDisagreement {
                field: "observed_at_unix",
            },
        });
    }
    let dto_contract = decode_lower_hex_32(&dto.contract.id)
        .map_err(|_| AdcosError::Malformed { reason: MalformedReason::BadRefId })?;
    if dto_contract != *statement.contract_ref() {
        return Err(AdcosError::Malformed {
            reason: MalformedReason::ObservationDisagreement { field: "contract" },
        });
    }
    if dto.sequence != statement.sequence() {
        return Err(AdcosError::Malformed {
            reason: MalformedReason::ObservationDisagreement { field: "sequence" },
        });
    }
    Ok(())
}

/// Parse the `GET /contracts/{id}/execution` success body (state-text bound
/// enforced at construction).
pub fn parse_execution_body(body: &[u8]) -> Result<ConnectivityExecutionProjection, AdcosError> {
    let parsed: ExecutionBody = decode(body)?;
    let contract = parse_contract_ref(&parsed.contract_ref)?;
    ConnectivityExecutionProjection::new(
        contract,
        parsed.state,
        parsed.throughput_bps,
        parsed.latency_ms,
        parsed.freshness_unix,
    )
    .map_err(AdcosError::Port)
}

// ---------------------------------------------------------------------------
// Error envelope (both directions)
// ---------------------------------------------------------------------------

/// The error envelope: `{"error": WireErrorBody}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireErrorEnvelope {
    /// The envelope body.
    pub error: WireErrorBody,
}

/// The typed error fields — all optional except `code`; the per-code table
/// above says which are expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireErrorBody {
    /// A `PortError` machine name.
    pub code: String,
    /// For `intent_unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<WireRef>,
    /// For `offer_unknown` / `offer_not_for_intent` / `offer_already_consumed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<WireRef>,
    /// For `offer_not_for_intent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed_intent: Option<WireRef>,
    /// For `contract_unknown` / `contract_terminated` / `offer_already_consumed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<WireRef>,
    /// For `requirement_version_unsupported`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<u64>,
    /// For `region_hint_too_long` / `execution_state_text_too_long`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// For `region_hint_too_long` / `execution_state_text_too_long`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// For `validity_window_invalid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from_unix: Option<u64>,
    /// For `validity_window_invalid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until_unix: Option<u64>,
    /// For `ref_kind_mismatch` (machine name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_kind: Option<String>,
    /// For `ref_kind_mismatch` (machine name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_kind: Option<String>,
    /// For `provider_unavailable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observation_fresh_until_unix: Option<u64>,
}

impl WireErrorBody {
    /// An envelope with only the code set.
    pub fn with_code(code: &str) -> WireErrorBody {
        WireErrorBody {
            code: code.to_string(),
            ..WireErrorBody::empty()
        }
    }

    /// The all-`None` body (used with struct-update syntax).
    pub fn empty() -> WireErrorBody {
        WireErrorBody {
            code: String::new(),
            intent: None,
            offer: None,
            passed_intent: None,
            contract: None,
            found: None,
            len: None,
            max: None,
            valid_from_unix: None,
            valid_until_unix: None,
            expected_kind: None,
            found_kind: None,
            last_observation_fresh_until_unix: None,
        }
    }
}

/// The documented HTTP status for a `PortError` machine name (the
/// code↔status pairing of this wire contract).
pub fn error_status(code: &str) -> u16 {
    match code {
        "requirement_version_unsupported" | "region_hint_too_long" => 400,
        "acquisition_unauthorized" => 401,
        "intent_unknown" | "offer_unknown" | "contract_unknown" => 404,
        "offer_not_for_intent" | "offer_already_consumed" | "contract_terminated" => 409,
        "validity_window_invalid" | "execution_state_text_too_long" | "ref_kind_mismatch" => 422,
        "provider_unavailable" => 503,
        _ => 400,
    }
}

/// Whether the code is one of the wire vocabulary's `PortError` machine names.
pub fn is_known_error_code(code: &str) -> bool {
    matches!(
        code,
        "requirement_version_unsupported"
            | "region_hint_too_long"
            | "acquisition_unauthorized"
            | "intent_unknown"
            | "offer_unknown"
            | "contract_unknown"
            | "offer_not_for_intent"
            | "offer_already_consumed"
            | "contract_terminated"
            | "validity_window_invalid"
            | "execution_state_text_too_long"
            | "ref_kind_mismatch"
            | "provider_unavailable"
    )
}

/// Encode a `PortError` as the wire error envelope: `(status, body bytes)`.
///
/// Used by the test scaffolding server so the code↔status table lives in
/// exactly one place (this module).
pub fn port_error_response(error: &PortError) -> (u16, Vec<u8>) {
    let body = match error.clone() {
        PortError::RequirementVersionUnsupported { found } => WireErrorBody {
            found: Some(u64::from(found)),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::RegionHintTooLong { len, max } => WireErrorBody {
            len: Some(len as u64),
            max: Some(max as u64),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::ValidityWindowInvalid { valid_from_unix, valid_until_unix } => WireErrorBody {
            valid_from_unix: Some(valid_from_unix),
            valid_until_unix: Some(valid_until_unix),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::ExecutionStateTextTooLong { len, max } => WireErrorBody {
            len: Some(len as u64),
            max: Some(max as u64),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::RefKindMismatch { expected, found } => WireErrorBody {
            expected_kind: Some(expected.as_str().to_string()),
            found_kind: Some(found.as_str().to_string()),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::IntentUnknown { intent } => WireErrorBody {
            intent: Some(ref_to_wire(RefKind::Intent, intent.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::OfferUnknown { offer } => WireErrorBody {
            offer: Some(ref_to_wire(RefKind::Offer, offer.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::OfferNotForIntent { offer, passed_intent } => WireErrorBody {
            offer: Some(ref_to_wire(RefKind::Offer, offer.id())),
            passed_intent: Some(ref_to_wire(RefKind::Intent, passed_intent.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::OfferAlreadyConsumed { offer, contract } => WireErrorBody {
            offer: Some(ref_to_wire(RefKind::Offer, offer.id())),
            contract: Some(ref_to_wire(RefKind::Contract, contract.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::ContractUnknown { contract } => WireErrorBody {
            contract: Some(ref_to_wire(RefKind::Contract, contract.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::ContractTerminated { contract } => WireErrorBody {
            contract: Some(ref_to_wire(RefKind::Contract, contract.id())),
            ..WireErrorBody::with_code(error.name())
        },
        PortError::ProviderUnavailable { last_observation_fresh_until_unix } => WireErrorBody {
            last_observation_fresh_until_unix,
            ..WireErrorBody::with_code(error.name())
        },
        PortError::AcquisitionUnauthorized => WireErrorBody::with_code(error.name()),
    };
    let status = error_status(&body.code);
    let envelope = WireErrorEnvelope { error: body };
    let bytes = encode(&envelope).expect("serializing the error envelope cannot fail");
    (status, bytes)
}

/// Map an error response (status + envelope body bytes) to the typed
/// [`AdcosError`].
///
/// The `code` is the typed truth; the HTTP status must be the documented
/// pairing, otherwise the response is malformed
/// ([`MalformedReason::CodeStatusMismatch`]) — a server that cannot keep
/// its own status table straight is not trusted to report its errors.
pub fn map_error_response(status: u16, body: &[u8]) -> AdcosError {
    let parsed: Result<WireErrorEnvelope, _> = serde_json::from_slice(body);
    let Ok(envelope) = parsed else {
        return AdcosError::Malformed { reason: MalformedReason::BadJson };
    };
    let error = envelope.error;
    if !is_known_error_code(&error.code) {
        return AdcosError::Malformed {
            reason: MalformedReason::UnknownErrorCode(error.code.clone()),
        };
    }
    if status != error_status(&error.code) {
        return AdcosError::Malformed {
            reason: MalformedReason::CodeStatusMismatch { code: error.code.clone(), status },
        };
    }
    match map_error_body(&error) {
        Ok(port) => AdcosError::Port(port),
        Err(reason) => AdcosError::Malformed { reason },
    }
}

/// The per-code field extraction. Reference fields inside an error envelope
/// are parsed STRICTLY (exact kind, strict hex) — an envelope whose fields
/// do not decode is itself malformed.
fn map_error_body(body: &WireErrorBody) -> Result<PortError, MalformedReason> {
    let code = body.code.as_str();
    match code {
        "requirement_version_unsupported" => Ok(PortError::RequirementVersionUnsupported {
            found: u32::try_from(body.found.ok_or(MalformedReason::MissingField("found"))?)
                .map_err(|_| MalformedReason::BadJson)?,
        }),
        "region_hint_too_long" => Ok(PortError::RegionHintTooLong {
            len: usize::try_from(body.len.ok_or(MalformedReason::MissingField("len"))?)
                .map_err(|_| MalformedReason::BadJson)?,
            max: usize::try_from(body.max.ok_or(MalformedReason::MissingField("max"))?)
                .map_err(|_| MalformedReason::BadJson)?,
        }),
        "validity_window_invalid" => Ok(PortError::ValidityWindowInvalid {
            valid_from_unix: body
                .valid_from_unix
                .ok_or(MalformedReason::MissingField("valid_from_unix"))?,
            valid_until_unix: body
                .valid_until_unix
                .ok_or(MalformedReason::MissingField("valid_until_unix"))?,
        }),
        "execution_state_text_too_long" => Ok(PortError::ExecutionStateTextTooLong {
            len: usize::try_from(body.len.ok_or(MalformedReason::MissingField("len"))?)
                .map_err(|_| MalformedReason::BadJson)?,
            max: usize::try_from(body.max.ok_or(MalformedReason::MissingField("max"))?)
                .map_err(|_| MalformedReason::BadJson)?,
        }),
        "ref_kind_mismatch" => {
            let expected = body
                .expected_kind
                .as_deref()
                .and_then(RefKind::from_name)
                .ok_or(MalformedReason::MissingField("expected_kind"))?;
            let found = body
                .found_kind
                .as_deref()
                .and_then(RefKind::from_name)
                .ok_or(MalformedReason::MissingField("found_kind"))?;
            Ok(PortError::RefKindMismatch { expected, found })
        }
        "intent_unknown" => Ok(PortError::IntentUnknown {
            intent: envelope_intent(body)?,
        }),
        "offer_unknown" => Ok(PortError::OfferUnknown {
            offer: envelope_offer(body)?,
        }),
        "offer_not_for_intent" => Ok(PortError::OfferNotForIntent {
            offer: envelope_offer(body)?,
            passed_intent: envelope_intent_named(body, "passed_intent")?,
        }),
        "offer_already_consumed" => Ok(PortError::OfferAlreadyConsumed {
            offer: envelope_offer(body)?,
            contract: envelope_contract(body)?,
        }),
        "contract_unknown" => Ok(PortError::ContractUnknown {
            contract: envelope_contract(body)?,
        }),
        "contract_terminated" => Ok(PortError::ContractTerminated {
            contract: envelope_contract(body)?,
        }),
        "provider_unavailable" => Ok(PortError::ProviderUnavailable {
            last_observation_fresh_until_unix: body.last_observation_fresh_until_unix,
        }),
        "acquisition_unauthorized" => Ok(PortError::AcquisitionUnauthorized),
        _ => Err(MalformedReason::UnknownErrorCode(body.code.clone())),
    }
}

/// Strict intent ref from the envelope's `intent` field.
fn envelope_intent(body: &WireErrorBody) -> Result<ConnectivityIntentRef, MalformedReason> {
    envelope_intent_named(body, "intent")
}

fn envelope_intent_named(
    body: &WireErrorBody,
    field: &'static str,
) -> Result<ConnectivityIntentRef, MalformedReason> {
    let wire = match (field, &body.intent, &body.passed_intent) {
        ("intent", Some(wire), _) => wire,
        ("passed_intent", _, Some(wire)) => wire,
        _ => return Err(MalformedReason::MissingField(field)),
    };
    if wire.kind != RefKind::Intent.as_str() {
        return Err(MalformedReason::UnknownRefKind(wire.kind.clone()));
    }
    ConnectivityIntentRef::from_parts(
        RefKind::Intent,
        decode_lower_hex_32(&wire.id)?,
    )
    .map_err(|_| MalformedReason::UnknownRefKind(wire.kind.clone()))
}

fn envelope_offer(body: &WireErrorBody) -> Result<ConnectivityOfferRef, MalformedReason> {
    let wire = body.offer.as_ref().ok_or(MalformedReason::MissingField("offer"))?;
    if wire.kind != RefKind::Offer.as_str() {
        return Err(MalformedReason::UnknownRefKind(wire.kind.clone()));
    }
    ConnectivityOfferRef::from_parts(RefKind::Offer, decode_lower_hex_32(&wire.id)?)
        .map_err(|_| MalformedReason::UnknownRefKind(wire.kind.clone()))
}

fn envelope_contract(body: &WireErrorBody) -> Result<ConnectivityContractRef, MalformedReason> {
    let wire = body
        .contract
        .as_ref()
        .ok_or(MalformedReason::MissingField("contract"))?;
    if wire.kind != RefKind::Contract.as_str() {
        return Err(MalformedReason::UnknownRefKind(wire.kind.clone()));
    }
    ConnectivityContractRef::from_parts(RefKind::Contract, decode_lower_hex_32(&wire.id)?)
        .map_err(|_| MalformedReason::UnknownRefKind(wire.kind.clone()))
}

/// Contract state machine-name parse. The parent exposes `as_str` but no
/// `from_name`; this mirror is unit-tested against the parent's full
/// `as_str` set so the two cannot drift.
pub fn contract_state_from_name(
    name: &str,
) -> Result<sharenet_connectivity::ContractState, AdcosError> {
    match name {
        "projected" => Ok(sharenet_connectivity::ContractState::Projected),
        "active" => Ok(sharenet_connectivity::ContractState::Active),
        "degraded" => Ok(sharenet_connectivity::ContractState::Degraded),
        "terminated" => Ok(sharenet_connectivity::ContractState::Terminated),
        other => Err(AdcosError::Malformed {
            reason: MalformedReason::UnknownContractState(other.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_connectivity::{
        ConnectivityContractRef, ConnectivityIntentRef, ConnectivityOfferRef, ContractState,
        ServiceClass,
    };

    const ID_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn intent() -> ConnectivityIntentRef {
        ConnectivityIntentRef::from_parts(RefKind::Intent, [1u8; 32]).unwrap()
    }

    /// The intent used by the literal-byte tests (ID_HEX is its hex form).
    fn hex_intent() -> ConnectivityIntentRef {
        ConnectivityIntentRef::from_parts(RefKind::Intent, decode_lower_hex_32(ID_HEX).unwrap())
            .unwrap()
    }

    fn offer() -> ConnectivityOfferRef {
        ConnectivityOfferRef::from_parts(RefKind::Offer, [2u8; 32]).unwrap()
    }

    fn contract() -> ConnectivityContractRef {
        ConnectivityContractRef::from_parts(RefKind::Contract, [3u8; 32]).unwrap()
    }

    fn contract_hex() -> String {
        encode_lower_hex(&[3u8; 32])
    }

    #[test]
    fn requirement_body_is_the_documented_json() {
        let requirement = ConnectivityRequirement::new(ServiceClass::Live)
            .with_max_cost_hint(1000)
            .with_max_latency_ms_hint(250)
            .with_region_hint("eu-central");
        assert_eq!(
            String::from_utf8(requirement_body(&requirement).unwrap()).unwrap(),
            r#"{"version":1,"service_class":"live","max_cost_hint":1000,"max_latency_ms_hint":250,"region_hint":"eu-central"}"#
        );
        // Hints are omitted, not null-ed.
        let bare = ConnectivityRequirement::new(ServiceClass::Dtn);
        assert_eq!(
            String::from_utf8(requirement_body(&bare).unwrap()).unwrap(),
            r#"{"version":1,"service_class":"dtn"}"#
        );
    }

    #[test]
    fn request_builders_are_the_documented_endpoint_table() {
        let i = intent();
        let o = offer();
        let c = contract();
        let requirement = intents_request(&ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
        assert_eq!(requirement.method, Method::Post);
        assert_eq!(requirement.path, "/intents");

        assert_eq!(offers_request(&i).method, Method::Get);
        assert_eq!(
            offers_request(&i).path,
            format!("/intents/{}/offers", encode_lower_hex(&[1u8; 32]))
        );
        let accept = accept_request(&i, &o);
        assert_eq!(accept.method, Method::Post);
        assert_eq!(
            accept.path,
            format!(
                "/intents/{}/offers/{}/accept",
                encode_lower_hex(&[1u8; 32]),
                encode_lower_hex(&[2u8; 32])
            )
        );
        assert_eq!(contract_request(&c).path, format!("/contracts/{}", contract_hex()));
        assert_eq!(
            assurance_request(&c).path,
            format!("/contracts/{}/assurance", contract_hex())
        );
        assert_eq!(
            execution_request(&c).path,
            format!("/contracts/{}/execution", contract_hex())
        );
        let terminate = terminate_request(&c);
        assert_eq!(terminate.method, Method::Post);
        assert_eq!(terminate.path, format!("/contracts/{}/terminate", contract_hex()));
        assert_eq!(terminate.body, b"{}");
    }

    #[test]
    fn intent_ref_body_parses_and_round_trips() {
        let body = format!(r#"{{"intent_ref":{{"kind":"intent","id":"{ID_HEX}"}}}}"#);
        let parsed = parse_intent_ref_body(body.as_bytes()).unwrap();
        assert_eq!(parsed, hex_intent());
        // The encoded form of the same ref is byte-identical.
        let wire = ref_to_wire(RefKind::Intent, hex_intent().id());
        assert_eq!(
            String::from_utf8(encode(&IntentRefBody { intent_ref: wire }).unwrap()).unwrap(),
            body
        );
    }

    #[test]
    fn wrong_and_unknown_ref_kinds_are_typed_rejected() {
        // Known but wrong kind: typed RefKindMismatch (the from_parts seam).
        let wrong = format!(r#"{{"intent_ref":{{"kind":"offer","id":"{ID_HEX}"}}}}"#);
        assert_eq!(
            parse_intent_ref_body(wrong.as_bytes()),
            Err(AdcosError::Port(PortError::RefKindMismatch {
                expected: RefKind::Intent,
                found: RefKind::Offer,
            }))
        );
        // Unknown kind: malformed.
        let unknown = format!(r#"{{"intent_ref":{{"kind":"lease","id":"{ID_HEX}"}}}}"#);
        assert_eq!(
            parse_intent_ref_body(unknown.as_bytes()),
            Err(AdcosError::Malformed {
                reason: MalformedReason::UnknownRefKind("lease".to_string())
            })
        );
    }

    #[test]
    fn ref_ids_are_strict_hex() {
        let long = format!(r#"{{"intent_ref":{{"kind":"intent","id":"{}0"}}}}"#, "0".repeat(64));
        assert_eq!(
            parse_intent_ref_body(long.as_bytes()),
            Err(AdcosError::Malformed { reason: MalformedReason::BadRefId })
        );
        let upper = format!(r#"{{"intent_ref":{{"kind":"intent","id":"{}"}}}}"#, "A".repeat(64));
        assert_eq!(
            parse_intent_ref_body(upper.as_bytes()),
            Err(AdcosError::Malformed { reason: MalformedReason::BadRefId })
        );
    }

    #[test]
    fn offers_body_parses_into_a_vec_of_refs() {
        let body = format!(
            r#"[{{"kind":"offer","id":"{ID_HEX}"}},{{"kind":"offer","id":"{ID_HEX}"}}]"#
        );
        let parsed = parse_offer_refs_body(body.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().all(|o| o.kind() == RefKind::Offer));
    }

    #[test]
    fn projection_body_parses_and_enforces_the_window() {
        let body = format!(
            r#"{{"contract_ref":{{"kind":"contract","id":"{}"}},"state":"active","valid_from_unix":100,"valid_until_unix":200,"freshness_unix":150}}"#,
            contract_hex()
        );
        let parsed = parse_projection_body(body.as_bytes()).unwrap();
        assert_eq!(parsed.contract(), &contract());
        assert_eq!(parsed.state(), ContractState::Active);
        assert_eq!(parsed.valid_from_unix(), 100);
        assert_eq!(parsed.valid_until_unix(), 200);
        assert_eq!(parsed.freshness_unix(), 150);

        // Inverted window: the typed ValidityWindowInvalid, not a fabricated projection.
        let bad = body.replace("\"valid_from_unix\":100", "\"valid_from_unix\":300");
        assert_eq!(
            parse_projection_body(bad.as_bytes()),
            Err(AdcosError::Port(PortError::ValidityWindowInvalid {
                valid_from_unix: 300,
                valid_until_unix: 200,
            }))
        );
        // Unknown state vocabulary: malformed.
        let unknown = body.replace("\"active\"", "\"paused\"");
        assert_eq!(
            parse_projection_body(unknown.as_bytes()),
            Err(AdcosError::Malformed {
                reason: MalformedReason::UnknownContractState("paused".to_string())
            })
        );
    }

    #[test]
    fn observation_dtos_parse_all_six_adcos_event_kinds() {
        let kinds = [
            "contract_activated",
            "execution_state_changed",
            "degraded",
            "assurance_available",
            "failover_replan",
            "terminated",
        ];
        let elements: Vec<String> = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| {
                format!(
                    r#"{{"kind":"{kind}","observed_at_unix":{},"contract":{{"kind":"contract","id":"{}"}},"sequence":{}}}"#,
                    1000 + i,
                    contract_hex(),
                    i + 1
                )
            })
            .collect();
        let body = format!("[{}]", elements.join(","));
        let parsed = parse_observation_dtos(body.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 6);
        for (i, dto) in parsed.iter().enumerate() {
            assert_eq!(dto.kind, kinds[i]);
            assert_eq!(dto.sequence, (i + 1) as u64);
            assert_eq!(dto.contract.id, contract_hex());
            // the unsigned shape parses at the DTO level — the refusal is
            // the VERIFICATION path's job (typed, below)
            assert_eq!(dto.signed_envelope, None);
        }
        // Unknown kind: malformed with the evidence carried.
        let bad = format!(
            r#"[{{"kind":"invented","observed_at_unix":1,"contract":{{"kind":"contract","id":"{}"}},"sequence":1}}]"#,
            contract_hex()
        );
        assert_eq!(
            parse_observation_dtos(bad.as_bytes()),
            Err(AdcosError::Malformed {
                reason: MalformedReason::UnknownObservationKind("invented".to_string())
            })
        );
    }

    /// Build one signed observation DTO from a real provider identity —
    /// the same construction the adcos_test_server uses.
    fn signed_dto(
        provider: &sharenet_protocol::Identity,
        contract_ref: [u8; 32],
        kind: sharenet_protocol::EvidenceKind,
        observed_at: u64,
        sequence: u64,
        mutate: impl FnOnce(&mut ObservationBody),
    ) -> Vec<u8> {
        let statement = ConnectivityObservationStatement::new(
            provider,
            contract_ref,
            kind,
            observed_at,
            sequence,
            None,
        )
        .expect("statement builds");
        let signed = statement.sign(provider).expect("signs");
        let mut dto = ObservationBody {
            kind: kind.as_str().to_string(),
            observed_at_unix: observed_at,
            contract: ref_to_wire(RefKind::Contract, &contract_ref),
            sequence,
            signed_envelope: Some(encode_lower_hex(&signed.to_envelope_bytes())),
        };
        mutate(&mut dto);
        serde_json::to_vec(&[dto]).expect("serialize dto body")
    }

    #[test]
    fn verified_observations_flow_and_unsigned_is_refused() {
        use sharenet_protocol::{ConnectivityEvidenceError, EvidenceKind, Identity};

        let provider = Identity::from_seed([0xA1; 32], 0, None).expect("provider");
        let contract_ref = [3u8; 32]; // the `contract()` test helper's id
        let mut admission = ObservationAdmission::new(600);
        admission.register_contract(contract_ref);

        // Valid signed observation → verified into the domain, fields taken
        // from the SIGNED statement.
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |_| {});
        let dtos = parse_observation_dtos(&body).unwrap();
        let verified = verify_observation_dtos(&dtos, &mut admission, 1_050).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].kind().as_str(), "degraded");
        assert_eq!(verified[0].observed_at_unix(), 1_000);
        assert_eq!(verified[0].sequence(), 1);
        assert_eq!(verified[0].contract(), &contract());

        // Unsigned (the pre-R5-004 shape): typed refusal, nothing returned.
        let unsigned = format!(
            r#"[{{"kind":"degraded","observed_at_unix":1000,"contract":{{"kind":"contract","id":"{}"}},"sequence":1}}]"#,
            contract_hex()
        );
        let dtos = parse_observation_dtos(unsigned.as_bytes()).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed { reason: MalformedReason::UnsignedObservation })
        );

        // Envelope not lowercase hex.
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_010, 2, |dto| {
            dto.signed_envelope = Some("NOT HEX".to_string());
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed { reason: MalformedReason::SignedEnvelopeNotHex })
        );

        // Tampered signature bytes inside the envelope hex.
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_010, 2, |dto| {
            let mut hex = dto.signed_envelope.take().unwrap();
            // flip one hex digit inside the 64-byte signature (the tail of
            // the envelope): the last hex character
            let last = hex.pop().unwrap();
            hex.push(if last == '0' { '1' } else { '0' });
            dto.signed_envelope = Some(hex);
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Evidence(ConnectivityEvidenceError::SignatureInvalid))
        );

        // The signature from a DIFFERENT key (forged envelope).
        let foreign = Identity::from_seed([0xEE; 32], 0, None).expect("foreign");
        let statement = ConnectivityObservationStatement::new(
            &provider,
            contract_ref,
            EvidenceKind::Degraded,
            1_010,
            2,
            None,
        )
        .unwrap();
        let raw = statement.to_wire_bytes();
        let forged = SignedConnectivityObservation::from_parts(raw.clone(), foreign.sign_detached(&raw));
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_010, 2, |dto| {
            dto.signed_envelope = Some(encode_lower_hex(&forged.to_envelope_bytes()));
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Evidence(ConnectivityEvidenceError::SignatureInvalid))
        );
    }

    #[test]
    fn observation_wrapper_disagreement_is_refused() {
        use sharenet_protocol::EvidenceKind;

        let provider = sharenet_protocol::Identity::from_seed([0xA2; 32], 0, None).expect("p");
        let contract_ref = [3u8; 32];
        let mut admission = ObservationAdmission::new(600);
        admission.register_contract(contract_ref);

        // kind rewritten in the JSON wrapper (signature still valid over the
        // original bytes — the signed bytes win, the wrapper is refused)
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |dto| {
            dto.kind = "terminated".to_string();
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed {
                reason: MalformedReason::ObservationDisagreement { field: "kind" }
            })
        );
        // observed_at rewritten
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |dto| {
            dto.observed_at_unix = 1_999;
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed {
                reason: MalformedReason::ObservationDisagreement { field: "observed_at_unix" }
            })
        );
        // sequence rewritten
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |dto| {
            dto.sequence = 7;
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed {
                reason: MalformedReason::ObservationDisagreement { field: "sequence" }
            })
        );
        // contract rewritten (a different contract's hex in the wrapper)
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |dto| {
            dto.contract = ref_to_wire(RefKind::Contract, &[9u8; 32]);
        });
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Malformed {
                reason: MalformedReason::ObservationDisagreement { field: "contract" }
            })
        );
        // and the failed attempts never advanced the sequence gate
        assert_eq!(admission.highest_sequence(&provider.node_id(), &contract_ref), None);
    }

    #[test]
    fn observation_admission_paths_are_typed_at_the_wire() {
        use sharenet_protocol::{ConnectivityEvidenceError, EvidenceKind, Identity};

        let provider = Identity::from_seed([0xA3; 32], 0, None).expect("p");
        let contract_ref = [3u8; 32];

        // unknown contract: the known-contract rule (never a trust grant)
        let mut admission = ObservationAdmission::new(600);
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |_| {});
        let dtos = parse_observation_dtos(&body).unwrap();
        assert!(matches!(
            verify_observation_dtos(&dtos, &mut admission, 1_050),
            Err(AdcosError::Evidence(ConnectivityEvidenceError::ContractUnknown { .. }))
        ));

        // freshness edges (bound exclusive): inside → verified, at/after the
        // bound → expired, before observed_at → not_yet_valid
        admission.register_contract(contract_ref);
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_000, 1, |_| {});
        let dtos = parse_observation_dtos(&body).unwrap();
        assert_eq!(
            verify_observation_dtos(&dtos, &mut admission, 1_599).unwrap()[0].sequence(),
            1,
            "inside the window verifies"
        );
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_700, 2, |_| {});
        let dtos = parse_observation_dtos(&body).unwrap();
        assert!(matches!(
            verify_observation_dtos(&dtos, &mut admission, 1_699),
            Err(AdcosError::Evidence(ConnectivityEvidenceError::NotYetValid { .. }))
        ));
        assert!(matches!(
            verify_observation_dtos(&dtos, &mut admission, 2_300),
            Err(AdcosError::Evidence(ConnectivityEvidenceError::Expired { .. }))
        ));

        // a verified redelivery (sequence already seen) still returns the
        // observation — dedup is the consumer's policy — and a strictly
        // greater sequence continues
        let body = signed_dto(&provider, contract_ref, EvidenceKind::Degraded, 1_800, 5, |_| {});
        let dtos = parse_observation_dtos(&body).unwrap();
        let verified = verify_observation_dtos(&dtos, &mut admission, 1_810).unwrap();
        assert_eq!(verified[0].sequence(), 5);
        let replay = verify_observation_dtos(&dtos, &mut admission, 1_810).unwrap();
        assert_eq!(replay[0].sequence(), 5, "verified redelivery is returned, not applied twice");
        assert_eq!(admission.highest_sequence(&provider.node_id(), &contract_ref), Some(5));
    }

    #[test]
    fn execution_body_parses_and_enforces_the_state_text_bound() {
        let body = format!(
            r#"{{"contract_ref":{{"kind":"contract","id":"{}"}},"state":"active","throughput_bps":42000000,"latency_ms":37,"freshness_unix":200}}"#,
            contract_hex()
        );
        let parsed = parse_execution_body(body.as_bytes()).unwrap();
        assert_eq!(parsed.contract(), &contract());
        assert_eq!(parsed.state(), "active");
        assert_eq!(parsed.throughput_bps(), 42_000_000);
        assert_eq!(parsed.latency_ms(), 37);
        assert_eq!(parsed.freshness_unix(), 200);

        let long = "x".repeat(sharenet_connectivity::MAX_EXECUTION_STATE_TEXT_BYTES + 1);
        let bad = format!(
            r#"{{"contract_ref":{{"kind":"contract","id":"{}"}},"state":"{long}","throughput_bps":1,"latency_ms":1,"freshness_unix":1}}"#,
            contract_hex()
        );
        assert_eq!(
            parse_execution_body(bad.as_bytes()),
            Err(AdcosError::Port(PortError::ExecutionStateTextTooLong {
                len: sharenet_connectivity::MAX_EXECUTION_STATE_TEXT_BYTES + 1,
                max: sharenet_connectivity::MAX_EXECUTION_STATE_TEXT_BYTES,
            }))
        );
    }

    #[test]
    fn bodies_that_are_not_the_shape_are_bad_json() {
        assert_eq!(
            parse_intent_ref_body(b"not json at all"),
            Err(AdcosError::Malformed { reason: MalformedReason::BadJson })
        );
        assert_eq!(
            parse_intent_ref_body(b"[]"),
            Err(AdcosError::Malformed { reason: MalformedReason::BadJson })
        );
        // Missing field.
        assert_eq!(
            parse_intent_ref_body(b"{}"),
            Err(AdcosError::Malformed { reason: MalformedReason::BadJson })
        );
    }

    #[test]
    fn every_port_error_round_trips_through_the_error_envelope() {
        // The full typed mapping table: every PortError machine name
        // encodes to (status, envelope) and maps back to the same error.
        let errors = vec![
            PortError::RequirementVersionUnsupported { found: 2 },
            PortError::RegionHintTooLong { len: 65, max: 64 },
            PortError::ValidityWindowInvalid { valid_from_unix: 9, valid_until_unix: 8 },
            PortError::ExecutionStateTextTooLong { len: 129, max: 128 },
            PortError::RefKindMismatch { expected: RefKind::Contract, found: RefKind::Offer },
            PortError::IntentUnknown { intent: intent() },
            PortError::OfferUnknown { offer: offer() },
            PortError::OfferNotForIntent { offer: offer(), passed_intent: intent() },
            PortError::OfferAlreadyConsumed { offer: offer(), contract: contract() },
            PortError::ContractUnknown { contract: contract() },
            PortError::ContractTerminated { contract: contract() },
            PortError::ProviderUnavailable { last_observation_fresh_until_unix: Some(1600) },
            PortError::ProviderUnavailable { last_observation_fresh_until_unix: None },
            PortError::AcquisitionUnauthorized,
        ];
        for error in &errors {
            let (status, body) = port_error_response(error);
            assert_eq!(
                map_error_response(status, &body),
                AdcosError::Port(error.clone()),
                "round trip failed for {}",
                error.name()
            );
        }
        // The pairing table is exactly as documented.
        assert_eq!(error_status("requirement_version_unsupported"), 400);
        assert_eq!(error_status("region_hint_too_long"), 400);
        assert_eq!(error_status("acquisition_unauthorized"), 401);
        assert_eq!(error_status("intent_unknown"), 404);
        assert_eq!(error_status("contract_unknown"), 404);
        assert_eq!(error_status("contract_terminated"), 409);
        assert_eq!(error_status("validity_window_invalid"), 422);
        assert_eq!(error_status("provider_unavailable"), 503);
    }

    #[test]
    fn error_envelope_faults_are_typed() {
        // Unknown code.
        let unknown = br#"{"error":{"code":"totally_new_failure"}}"#;
        assert_eq!(
            map_error_response(400, unknown),
            AdcosError::Malformed {
                reason: MalformedReason::UnknownErrorCode("totally_new_failure".to_string())
            }
        );
        // Known code with the wrong status: the pairing is part of the contract.
        let (status, body) = port_error_response(&PortError::ContractTerminated { contract: contract() });
        let mispaired = 404u16;
        assert_ne!(status, mispaired);
        assert_eq!(
            map_error_response(mispaired, &body),
            AdcosError::Malformed {
                reason: MalformedReason::CodeStatusMismatch {
                    code: "contract_terminated".to_string(),
                    status: 404,
                }
            }
        );
        // Unparseable envelope.
        assert_eq!(
            map_error_response(503, b"<html>garbage</html>"),
            AdcosError::Malformed { reason: MalformedReason::BadJson }
        );
        // Known code, missing required field.
        assert_eq!(
            map_error_response(404, br#"{"error":{"code":"intent_unknown"}}"#),
            AdcosError::Malformed { reason: MalformedReason::MissingField("intent") }
        );
    }

    #[test]
    fn contract_state_names_cover_exactly_the_parents_set() {
        // The parent exposes as_str but no from_name; this mirror must
        // cover every parent name and refuse everything else.
        let parent_names = [
            ContractState::Projected,
            ContractState::Active,
            ContractState::Degraded,
            ContractState::Terminated,
        ]
        .map(|s| s.as_str().to_string());
        for name in &parent_names {
            let parsed = contract_state_from_name(name).expect("known parent name");
            assert_eq!(parsed.as_str(), name.as_str(), "round trip");
        }
        assert_eq!(
            contract_state_from_name("expired"),
            Err(AdcosError::Malformed {
                reason: MalformedReason::UnknownContractState("expired".to_string())
            })
        );
    }
}
