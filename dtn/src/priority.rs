//! The frozen service classes, as the DTN store's carry priority.
//!
//! `spec/adrs/003-service-classes.md` and the R3-004 route commitment froze
//! exactly three service classes — `live`, `opportunistic`, `dtn` — and the
//! protocol core exports them as `sharenet_protocol::SERVICE_CLASSES`. This
//! module is the same frozen set as a TYPED carry priority for bundle
//! records (the store's priority field, architecture §12 "priority"): a
//! unit test pins the two vocabularies together so they can never drift.
//!
//! Priority ordering for carry-forward (`rank`): `live` first (interactive
//! traffic degrades fastest), then `opportunistic`, then `dtn` (built to
//! wait). Within one class the carry-forward order is by expiry urgency,
//! then content id bytes (see `DtnStoreImage::forward_candidates`) — the
//! whole ordering is deterministic for a fixed store state (architecture
//! §2), never hash-iteration dependent.

use crate::error::DtnError;

/// The carry priority of a bundle: the frozen ShareNet service classes
/// (ADR-003), in carry order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServicePriority {
    /// The `live` service class: interactive traffic; carried first.
    Live,
    /// The `opportunistic` service class: best-effort; carried second.
    Opportunistic,
    /// The `dtn` service class: built to wait; carried last.
    Dtn,
}

impl ServicePriority {
    /// The frozen class name (wire/shared vocabulary).
    pub fn as_str(&self) -> &'static str {
        match self {
            ServicePriority::Live => "live",
            ServicePriority::Opportunistic => "opportunistic",
            ServicePriority::Dtn => "dtn",
        }
    }

    /// Parse from the frozen class name (probe + tests).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "live" => Some(ServicePriority::Live),
            "opportunistic" => Some(ServicePriority::Opportunistic),
            "dtn" => Some(ServicePriority::Dtn),
            _ => None,
        }
    }

    /// The carry rank (0 = carried first). Deterministic total order.
    pub fn rank(&self) -> u8 {
        match self {
            ServicePriority::Live => 0,
            ServicePriority::Opportunistic => 1,
            ServicePriority::Dtn => 2,
        }
    }

    pub(crate) fn tag(self) -> u8 {
        self.rank()
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(ServicePriority::Live),
            1 => Some(ServicePriority::Opportunistic),
            2 => Some(ServicePriority::Dtn),
            _ => None,
        }
    }
}

impl std::fmt::Display for ServicePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validate a priority tag read from the registry (typed failure).
pub(crate) fn priority_from_tag(tag: u8) -> Result<ServicePriority, DtnError> {
    ServicePriority::from_tag(tag)
        .ok_or(DtnError::PriorityTagInvalid { found: tag })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The priority vocabulary IS the frozen service-class set — no second
    /// vocabulary drift (the names are byte-compared against the protocol
    /// core's frozen constant, ADR-003).
    #[test]
    fn priority_vocabulary_is_the_frozen_service_class_set() {
        let frozen = sharenet_protocol::SERVICE_CLASSES;
        let priorities = [
            ServicePriority::Live,
            ServicePriority::Opportunistic,
            ServicePriority::Dtn,
        ];
        for (p, name) in priorities.iter().zip(frozen.iter()) {
            assert_eq!(p.as_str(), *name);
            assert_eq!(ServicePriority::from_name(name), Some(*p));
        }
        assert_eq!(frozen.len(), 3);
        assert_eq!(ServicePriority::from_name("bulk"), None);
        assert_eq!(ServicePriority::from_name(""), None);
        assert_eq!(ServicePriority::from_name("LIVE"), None, "case-sensitive");
    }

    #[test]
    fn rank_is_the_carry_order() {
        assert!(ServicePriority::Live.rank() < ServicePriority::Opportunistic.rank());
        assert!(ServicePriority::Opportunistic.rank() < ServicePriority::Dtn.rank());
        // The derived Ord agrees with the rank (used by sort keys).
        assert!(ServicePriority::Live < ServicePriority::Opportunistic);
        assert!(ServicePriority::Opportunistic < ServicePriority::Dtn);
    }

    #[test]
    fn tags_round_trip_and_reject_out_of_range() {
        for p in [ServicePriority::Live, ServicePriority::Opportunistic, ServicePriority::Dtn] {
            assert_eq!(ServicePriority::from_tag(p.tag()), Some(p));
        }
        for bad in [3u8, 4, 200, 255] {
            assert_eq!(ServicePriority::from_tag(bad), None);
            assert_eq!(
                priority_from_tag(bad),
                Err(DtnError::PriorityTagInvalid { found: bad })
            );
        }
    }
}
