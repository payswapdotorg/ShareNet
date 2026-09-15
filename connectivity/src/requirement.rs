//! The intent input — `ConnectivityRequirement`, the argument of
//! `ConnectivityPort::createIntent`.
//!
//! Minimal, plain data and future-extensible via a versioned struct: the
//! [`REQUIREMENT_VERSION`] field is validated at the port seam, so a later
//! version can add optional hint fields without silently reinterpreting old
//! ones. No provider-native anything: this is ShareNet's technology-neutral
//! description of the connectivity outcome it wants (ADR-001), which ADCOS
//! normalizes and matches against its providers.

use crate::error::PortError;

/// The requirement struct version understood by this wave.
pub const REQUIREMENT_VERSION: u32 = 1;

/// Maximum byte length of the optional region hint (UTF-8 bytes, not chars).
pub const MAX_REGION_HINT_BYTES: usize = 64;

/// The frozen service class set, mirroring ADR-003 (LIVE / OPPORTUNISTIC / DTN)
/// and the protocol core's route service classes.
///
/// Duplicated from `reference/crates/sharenet-protocol`'s `SERVICE_CLASSES`
/// BY DESIGN: this crate must not depend on the protocol core (independent
/// freezability — see the crate docs and `tools/architecture_check.py`), so
/// the frozen set is restated here and the Tech Lead keeps them in sync.
pub const SERVICE_CLASSES: [&str; 3] = ["live", "opportunistic", "dtn"];

/// Service class of a connectivity requirement — which of the three ShareNet
/// mission classes (ADR-003) the acquired outcome must serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceClass {
    /// Continuous path required.
    Live,
    /// Service may suspend and resume across connectivity opportunities.
    Opportunistic,
    /// Store-carry-forward delivery with deadline/TTL.
    Dtn,
}

impl ServiceClass {
    /// Stable machine name (matches the frozen `SERVICE_CLASSES` set).
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceClass::Live => "live",
            ServiceClass::Opportunistic => "opportunistic",
            ServiceClass::Dtn => "dtn",
        }
    }

    /// Parse from the machine name; `None` for anything outside the frozen set.
    pub fn from_name(name: &str) -> Option<ServiceClass> {
        match name {
            "live" => Some(ServiceClass::Live),
            "opportunistic" => Some(ServiceClass::Opportunistic),
            "dtn" => Some(ServiceClass::Dtn),
            _ => None,
        }
    }
}

/// The intent input of `ConnectivityPort::createIntent`.
///
/// Everything is a hint: ADCOS owns intent normalization, eligibility and
/// policy for acquired connectivity (architecture §4) — ShareNet only states
/// what outcome it wants. Cost and latency hints are plain `u64`s (no floats,
/// no units machinery); the region hint is bounded text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityRequirement {
    /// Struct version — must equal [`REQUIREMENT_VERSION`] to cross the port.
    pub version: u32,
    /// Which mission service class the outcome must serve (frozen set).
    pub service_class: ServiceClass,
    /// Optional ceiling on what the acquiring node is willing to pay
    /// (provider-defined cost units; interpreted by ADCOS).
    pub max_cost_hint: Option<u64>,
    /// Optional ceiling on acceptable latency, in milliseconds.
    pub max_latency_ms_hint: Option<u64>,
    /// Optional region hint (free text, at most [`MAX_REGION_HINT_BYTES`]
    /// UTF-8 bytes; interpreted by ADCOS).
    pub region_hint: Option<String>,
}

impl ConnectivityRequirement {
    /// A version-`REQUIREMENT_VERSION` requirement for the given service
    /// class, with no hints. Chain the `with_*` builders for optional hints.
    pub fn new(service_class: ServiceClass) -> Self {
        ConnectivityRequirement {
            version: REQUIREMENT_VERSION,
            service_class,
            max_cost_hint: None,
            max_latency_ms_hint: None,
            region_hint: None,
        }
    }

    /// Builder: attach a max-cost hint.
    pub fn with_max_cost_hint(mut self, max_cost: u64) -> Self {
        self.max_cost_hint = Some(max_cost);
        self
    }

    /// Builder: attach a max-latency hint in milliseconds.
    pub fn with_max_latency_ms_hint(mut self, max_latency_ms: u64) -> Self {
        self.max_latency_ms_hint = Some(max_latency_ms);
        self
    }

    /// Builder: attach a region hint.
    pub fn with_region_hint(mut self, region_hint: impl Into<String>) -> Self {
        self.region_hint = Some(region_hint.into());
        self
    }

    /// Validate before the requirement crosses the port seam.
    ///
    /// Enforces the struct version (future-extensibility contract) and the
    /// region-hint bound. The service class is an enum, so it is inside the
    /// frozen set by construction.
    pub fn validate(&self) -> Result<(), PortError> {
        if self.version != REQUIREMENT_VERSION {
            return Err(PortError::RequirementVersionUnsupported {
                found: self.version,
            });
        }
        if let Some(region) = &self.region_hint {
            let len = region.as_bytes().len();
            if len > MAX_REGION_HINT_BYTES {
                return Err(PortError::RegionHintTooLong {
                    len,
                    max: MAX_REGION_HINT_BYTES,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_requirements_pass() {
        ConnectivityRequirement::new(ServiceClass::Live).validate().unwrap();
        ConnectivityRequirement::new(ServiceClass::Opportunistic)
            .with_max_cost_hint(1000)
            .with_max_latency_ms_hint(250)
            .with_region_hint("eu-central")
            .validate()
            .unwrap();
        ConnectivityRequirement::new(ServiceClass::Dtn)
            .with_region_hint("x".repeat(MAX_REGION_HINT_BYTES))
            .validate()
            .unwrap();
    }

    #[test]
    fn version_is_enforced() {
        let mut requirement = ConnectivityRequirement::new(ServiceClass::Live);
        requirement.version = 2;
        assert_eq!(
            requirement.validate(),
            Err(PortError::RequirementVersionUnsupported { found: 2 })
        );
    }

    #[test]
    fn region_hint_bound_is_enforced() {
        let requirement = ConnectivityRequirement::new(ServiceClass::Live)
            .with_region_hint("x".repeat(MAX_REGION_HINT_BYTES + 1));
        assert_eq!(
            requirement.validate(),
            Err(PortError::RegionHintTooLong {
                len: MAX_REGION_HINT_BYTES + 1,
                max: MAX_REGION_HINT_BYTES,
            })
        );
    }

    #[test]
    fn service_class_set_is_the_frozen_adr003_set() {
        // Exactly the three ADR-003 classes, same machine names as the
        // protocol core's SERVICE_CLASSES (duplicated by design — see docs).
        for name in SERVICE_CLASSES {
            assert!(ServiceClass::from_name(name).is_some());
        }
        assert!(ServiceClass::from_name("best_effort").is_none());
        assert_eq!(ServiceClass::Live.as_str(), "live");
        assert_eq!(ServiceClass::Opportunistic.as_str(), "opportunistic");
        assert_eq!(ServiceClass::Dtn.as_str(), "dtn");
    }
}
