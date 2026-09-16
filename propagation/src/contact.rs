//! The contact model — work item R6-005's first half: the typed
//! encounter window the opportunistic forwarder decides inside.
//!
//! Architecture §12 lists "opportunistic forwarding" among the
//! propagation rules; R6-003's store named the seam explicitly ("WHERE
//! it goes (and whether now is a good moment) is the R6-005
//! opportunistic forwarder's decision, composed with the R5-005
//! gateway admission policy — only an `Eligible` gateway receives
//! bundles"). THIS module is the CONTACT: a bounded encounter window
//! with an admitted gateway, carried as typed state so the forwarder
//! ([`crate::forwarder`]) can be a pure function of it.
//!
//! A [`ContactOpportunity`] is:
//!
//! - **an admitted gateway** — the R5-005 [`GatewayAdmission`] verdict
//!   snapshot that is valid for the window (only an `Eligible` gateway
//!   receives bundles; an `Ineligible` verdict cannot construct a
//!   contact at all — fail-closed at the type boundary, never a boolean
//!   the forwarder re-checks);
//! - **a bound encounter** — the verdict must be ABOUT the contact's
//!   gateway (evidence never transfers, the R5-005 binding rule) and
//!   the window must fit INSIDE the verdict's `valid_until_unix`
//!   freshness bound (a window that outlives its evidence is not a
//!   contact; the caller splits it or re-admits);
//! - **a bounded budget** — what the encounter can carry: bytes and
//!   bundle count (radio duty cycle, gateway load, the honest
//!   constraint the forwarder composes its batch under);
//! - **caller-clocked** — `opens_at_unix`/`closes_at_unix` bound the
//!   window `[opens, closes)` (the store's exclusive-bound convention),
//!   and every clock the forwarder later evaluates is supplied by the
//!   caller. This crate has no wall clock, here as everywhere.
//!
//! Construction is fail-closed and typed ([`ContactError`], stable
//! machine names): `gateway_not_admitted` (with the verdict's own
//! reason names), `gateway_id_mismatch`, `window_outlives_admission`,
//! `empty_window`, `empty_budget`. A constructed
//! `ContactOpportunity` therefore CARRIES its invariants — the
//! forwarder never re-derives them.
//!
//! # The honest boundary
//!
//! The verdict is the R5-005 policy's OUTPUT, handed in as typed
//! evidence (the same composition position as R7-003's selection
//! stage, which re-runs the policy over signed evidence and hands the
//! result onward). An `Eligible` verdict is NOT a promise that the
//! gateway will deliver ShareNet packets (the R5-005 law); the
//! contact additionally requires only that the evidence be fresh for
//! the whole window. Re-deriving eligibility from signed topology +
//! ADCOS evidence at contact time is the daemon's job (it runs the
//! R5-005 policy); this layer consumes the derived verdict and checks
//! its binding and window coverage.

use sharenet_admission::GatewayAdmission;
use sharenet_dtn::PeerRef;

/// The node-id length of a gateway (the derived `NodeIdentity` id the
/// admission verdict binds to).
pub const GATEWAY_ID_LEN: usize = 32;

/// A typed contact-model construction failure (fail-closed; stable
/// machine names, the crate discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactError {
    /// The admission verdict is `Ineligible` — an ineligible gateway
    /// receives no bundles, so no contact exists to describe. Carries
    /// the verdict's own reason machine names, in its fixed order.
    GatewayNotAdmitted {
        /// The R5-005 verdict's typed reasons (machine names).
        reasons: Vec<&'static str>,
    },
    /// The verdict is about a DIFFERENT node than the contact names
    /// (the binding rule — evidence never transfers).
    GatewayIdMismatch {
        /// The gateway the verdict attests.
        verdict_gateway_node_id: [u8; GATEWAY_ID_LEN],
        /// The gateway the contact names.
        contact_gateway_node_id: [u8; GATEWAY_ID_LEN],
    },
    /// The window closes after the verdict's freshness bound — the
    /// evidence is not valid for the whole window. Split the window or
    /// re-admit.
    WindowOutlivesAdmission {
        /// The window's close (exclusive).
        closes_at_unix: u64,
        /// The verdict's freshness bound (exclusive).
        valid_until_unix: u64,
    },
    /// The window is degenerate (`opens >= closes`).
    EmptyWindow {
        /// The window's open tick.
        opens_at_unix: u64,
        /// The window's close tick.
        closes_at_unix: u64,
    },
    /// The budget carries nothing (zero bytes or zero bundles) — a
    /// contact that cannot move anything is not an opportunity.
    EmptyBudget,
}

impl ContactError {
    /// The stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ContactError::GatewayNotAdmitted { .. } => "gateway_not_admitted",
            ContactError::GatewayIdMismatch { .. } => "gateway_id_mismatch",
            ContactError::WindowOutlivesAdmission { .. } => "window_outlives_admission",
            ContactError::EmptyWindow { .. } => "empty_window",
            ContactError::EmptyBudget => "empty_budget",
        }
    }
}

impl std::fmt::Display for ContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContactError::GatewayNotAdmitted { reasons } => {
                write!(f, "gateway not admitted: ")?;
                for (i, reason) in reasons.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{reason}")?;
                }
                Ok(())
            }
            ContactError::GatewayIdMismatch {
                verdict_gateway_node_id,
                contact_gateway_node_id,
            } => {
                let hex = |bytes: &[u8]| {
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                write!(
                    f,
                    "verdict is about a different gateway than the contact names ({} vs {})",
                    hex(verdict_gateway_node_id),
                    hex(contact_gateway_node_id)
                )
            }
            ContactError::WindowOutlivesAdmission {
                closes_at_unix,
                valid_until_unix,
            } => write!(
                f,
                "window closes at {closes_at_unix} after the admission bound {valid_until_unix}"
            ),
            ContactError::EmptyWindow {
                opens_at_unix,
                closes_at_unix,
            } => {
                write!(f, "empty window [{opens_at_unix}, {closes_at_unix})")
            }
            ContactError::EmptyBudget => write!(f, "empty contact budget"),
        }
    }
}

/// What the encounter can carry: a byte bound and a bundle-count
/// bound (both strictly positive — see [`ContactError::EmptyBudget`]).
///
/// The bounds are CONTACT-LOCAL facts (the window's capacity), not
/// forwarder configuration: two windows with the same gateway may
/// carry different budgets, and the forwarder's policy
/// ([`crate::forwarder::OpportunisticForwarder`]) composes its batch
/// under whichever budget the contact carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactBudget {
    max_bytes: u64,
    max_bundles: u32,
}

impl ContactBudget {
    /// A budget allowing at most `max_bytes` payload bytes and
    /// `max_bundles` bundles per contact (both must be `>= 1`).
    pub fn new(max_bytes: u64, max_bundles: u32) -> Result<Self, ContactError> {
        if max_bytes == 0 || max_bundles == 0 {
            return Err(ContactError::EmptyBudget);
        }
        Ok(ContactBudget {
            max_bytes,
            max_bundles,
        })
    }

    /// The payload byte bound (manifest bytes + chunk bytes).
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// The bundle count bound.
    pub fn max_bundles(&self) -> u32 {
        self.max_bundles
    }
}

/// An encounter window with an admitted gateway: the typed input the
/// opportunistic forwarder plans inside (R6-005).
///
/// All invariants are checked at construction (see the module docs):
/// the verdict is `Eligible`, it is about THIS gateway, the window
/// `[opens_at_unix, closes_at_unix)` fits inside the verdict's
/// freshness bound, and the budget is non-degenerate. The type is
/// immutable thereafter — a contact is a snapshot, and the forwarder
/// is a pure function of (contact, store, clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactOpportunity<'a> {
    gateway_node_id: [u8; GATEWAY_ID_LEN],
    admission: &'a GatewayAdmission,
    opens_at_unix: u64,
    closes_at_unix: u64,
    budget: ContactBudget,
}

impl<'a> ContactOpportunity<'a> {
    /// Assemble the contact, fail-closed on every invariant (see the
    /// module docs for the checks and their order).
    pub fn new(
        gateway_node_id: [u8; GATEWAY_ID_LEN],
        admission: &'a GatewayAdmission,
        opens_at_unix: u64,
        closes_at_unix: u64,
        budget: ContactBudget,
    ) -> Result<Self, ContactError> {
        // 1. Only an admitted (Eligible) gateway receives bundles —
        //    the R6-003/R6-005 composition law. The verdict's own
        //    typed reasons ride along for honest reporting.
        let GatewayAdmission::Eligible {
            gateway_node_id: verdict_gateway,
            valid_until_unix,
            ..
        } = admission
        else {
            return Err(ContactError::GatewayNotAdmitted {
                reasons: admission
                    .reasons()
                    .iter()
                    .map(|reason| reason.as_str())
                    .collect(),
            });
        };
        // 2. The evidence must bind to the contact's gateway (the
        //    R5-005 binding rule — evidence never transfers).
        if *verdict_gateway != gateway_node_id {
            return Err(ContactError::GatewayIdMismatch {
                verdict_gateway_node_id: *verdict_gateway,
                contact_gateway_node_id: gateway_node_id,
            });
        }
        // 3. The window must be a window.
        if opens_at_unix >= closes_at_unix {
            return Err(ContactError::EmptyWindow {
                opens_at_unix,
                closes_at_unix,
            });
        }
        // 4. The evidence must be valid for the WHOLE window (the
        //    bound is exclusive, the close is exclusive: every tick
        //    of the window is strictly inside the bound iff
        //    closes <= valid_until).
        if closes_at_unix > *valid_until_unix {
            return Err(ContactError::WindowOutlivesAdmission {
                closes_at_unix,
                valid_until_unix: *valid_until_unix,
            });
        }
        // The budget was validated at its own construction.
        Ok(ContactOpportunity {
            gateway_node_id,
            admission,
            opens_at_unix,
            closes_at_unix,
            budget,
        })
    }

    /// The gateway this contact is with (the admission verdict's own
    /// subject — construction proved they agree).
    pub fn gateway_node_id(&self) -> &[u8; GATEWAY_ID_LEN] {
        &self.gateway_node_id
    }

    /// When the window opens (inclusive).
    pub fn opens_at_unix(&self) -> u64 {
        self.opens_at_unix
    }

    /// When the window closes (exclusive — the store's bound
    /// convention).
    pub fn closes_at_unix(&self) -> u64 {
        self.closes_at_unix
    }

    /// The admission verdict snapshot the contact rests on.
    pub fn admission(&self) -> &GatewayAdmission {
        self.admission
    }

    /// The verdict's freshness bound (exclusive) — construction
    /// proved the window fits inside it.
    pub fn valid_until_unix(&self) -> u64 {
        match self.admission {
            GatewayAdmission::Eligible {
                valid_until_unix, ..
            } => *valid_until_unix,
            // Construction proved Eligible; unreachable for a
            // constructed contact.
            GatewayAdmission::Ineligible { .. } => 0,
        }
    }

    /// The window's carrying bounds.
    pub fn budget(&self) -> &ContactBudget {
        &self.budget
    }

    /// The gateway as a custody [`PeerRef`] — the peer the sender's
    /// `note_forwarded` evidence names for handovers over this
    /// contact. (A 32-byte node id always fits the 64-byte bound.)
    pub fn peer_ref(&self) -> PeerRef {
        PeerRef::new(&self.gateway_node_id).expect("32 bytes fit the PeerRef bound")
    }

    /// Whether `now_unix` falls inside the window
    /// (`opens <= now < closes`).
    pub fn contains_clock(&self, now_unix: u64) -> bool {
        self.opens_at_unix <= now_unix && now_unix < self.closes_at_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_admission::{
        AdmissionReason, AdcosEvidenceAnchor, ShareNetEvidenceAnchor,
    };
    use sharenet_connectivity::{ContractState, ConnectivityContractRef};

    fn gateway_id(tag: u8) -> [u8; GATEWAY_ID_LEN] {
        let mut id = [0u8; GATEWAY_ID_LEN];
        id[0] = tag;
        id
    }

    /// A synthetic Eligible verdict about `gateway` valid until
    /// `valid_until` — the shape the R5-005 policy emits (anchors
    /// carrying what was admitted). Test scaffolding only; the real
    /// policy derives it from signed evidence.
    fn eligible(
        gateway: [u8; GATEWAY_ID_LEN],
        valid_until: u64,
    ) -> GatewayAdmission {
        GatewayAdmission::Eligible {
            gateway_node_id: gateway,
            sharenet: ShareNetEvidenceAnchor {
                link_id: [1; 32],
                observer_node_id: [2; 32],
                observed_at_unix: 1_000,
                expires_at_unix: valid_until,
                loss_ratio_ppm_effective: 0,
                p95_rtt_micros: 1_000,
                fresh_until_unix: valid_until,
            },
            adcos: AdcosEvidenceAnchor {
                contract: ConnectivityContractRef::from_id([3; 32]),
                state: ContractState::Active,
                fresh_until_unix: valid_until,
                last_observed_at_unix: 1_000,
                last_sequence: 1,
                provider_node_id: [4; 32],
            },
            valid_until_unix: valid_until,
        }
    }

    fn ineligible() -> GatewayAdmission {
        GatewayAdmission::Ineligible {
            reasons: vec![
                AdmissionReason::ShareNetEvidenceMissing,
                AdmissionReason::AdcosEvidenceMissing,
            ],
        }
    }

    fn budget() -> Result<ContactBudget, ContactError> {
        ContactBudget::new(10_000, 5)
    }

    /// The happy path: a well-formed window with an admitted gateway
    /// constructs, carrying exactly what was given.
    #[test]
    fn admitted_gateway_in_a_valid_window_constructs() {
        let gateway = gateway_id(7);
        let verdict = eligible(gateway, 2_000);
        let contact =
            ContactOpportunity::new(gateway, &verdict, 1_000, 1_100, budget().unwrap()).unwrap();
        assert_eq!(contact.gateway_node_id(), &gateway);
        assert_eq!(contact.opens_at_unix(), 1_000);
        assert_eq!(contact.closes_at_unix(), 1_100);
        assert_eq!(contact.valid_until_unix(), 2_000);
        assert_eq!(contact.budget().max_bytes(), 10_000);
        assert_eq!(contact.budget().max_bundles(), 5);
        assert!(contact.contains_clock(1_000), "inclusive open");
        assert!(contact.contains_clock(1_099), "inside");
        assert!(!contact.contains_clock(999), "before");
        assert!(!contact.contains_clock(1_100), "exclusive close");
        // The gateway's PeerRef is its node id (the custody peer the
        // sender's evidence will name).
        assert_eq!(contact.peer_ref().as_bytes(), &gateway);
    }

    /// An Ineligible verdict cannot construct a contact — the reasons
    /// ride along, machine-named.
    #[test]
    fn ineligible_gateway_never_constructs() {
        let gateway = gateway_id(7);
        let verdict = ineligible();
        let err = ContactOpportunity::new(gateway, &verdict, 1_000, 1_100, budget().unwrap())
            .unwrap_err();
        assert_eq!(err.name(), "gateway_not_admitted");
        assert_eq!(
            err,
            ContactError::GatewayNotAdmitted {
                reasons: vec!["sharenet_evidence_missing", "adcos_evidence_missing"],
            }
        );
        assert!(err.to_string().contains("sharenet_evidence_missing"));
    }

    /// A verdict about a different gateway does not bind — typed
    /// mismatch, never a silent transfer.
    #[test]
    fn evidence_never_transfers_to_another_gateway() {
        let verdict = eligible(gateway_id(7), 2_000);
        let err = ContactOpportunity::new(
            gateway_id(8),
            &verdict,
            1_000,
            1_100,
            budget().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.name(), "gateway_id_mismatch");
        assert_eq!(
            err,
            ContactError::GatewayIdMismatch {
                verdict_gateway_node_id: gateway_id(7),
                contact_gateway_node_id: gateway_id(8),
            }
        );
    }

    /// A window that closes past the evidence's freshness bound is
    /// refused — the evidence must cover the WHOLE window. Closing
    /// exactly at the bound is fine (both bounds are exclusive).
    #[test]
    fn window_must_fit_inside_the_admission_validity() {
        let gateway = gateway_id(7);
        let verdict = eligible(gateway, 2_000);
        // closes == valid_until: fine (the window is [1000, 2000),
        // every tick is < 2000).
        assert!(
            ContactOpportunity::new(gateway, &verdict, 1_000, 2_000, budget().unwrap()).is_ok()
        );
        // closes one tick past the bound: refused typed.
        let err = ContactOpportunity::new(gateway, &verdict, 1_000, 2_001, budget().unwrap())
            .unwrap_err();
        assert_eq!(err.name(), "window_outlives_admission");
        assert_eq!(
            err,
            ContactError::WindowOutlivesAdmission {
                closes_at_unix: 2_001,
                valid_until_unix: 2_000,
            }
        );
    }

    /// Degenerate windows and budgets are typed refusals.
    #[test]
    fn degenerate_windows_and_budgets_are_refused() {
        let gateway = gateway_id(7);
        let verdict = eligible(gateway, 2_000);
        let err =
            ContactOpportunity::new(gateway, &verdict, 1_100, 1_100, budget().unwrap()).unwrap_err();
        assert_eq!(err.name(), "empty_window");
        let err =
            ContactOpportunity::new(gateway, &verdict, 1_200, 1_100, budget().unwrap()).unwrap_err();
        assert_eq!(err.name(), "empty_window");
        assert!(ContactBudget::new(0, 5).unwrap_err() == ContactError::EmptyBudget);
        assert!(ContactBudget::new(10, 0).unwrap_err() == ContactError::EmptyBudget);
        assert_eq!(ContactError::EmptyBudget.name(), "empty_budget");
    }

    /// The error vocabulary is pinned distinct (no two names collide).
    #[test]
    fn error_names_are_distinct() {
        let names = [
            "gateway_not_admitted",
            "gateway_id_mismatch",
            "window_outlives_admission",
            "empty_window",
            "empty_budget",
        ];
        let all = [
            ContactError::GatewayNotAdmitted { reasons: vec![] },
            ContactError::GatewayIdMismatch {
                verdict_gateway_node_id: [0; GATEWAY_ID_LEN],
                contact_gateway_node_id: [1; GATEWAY_ID_LEN],
            },
            ContactError::WindowOutlivesAdmission {
                closes_at_unix: 1,
                valid_until_unix: 0,
            },
            ContactError::EmptyWindow {
                opens_at_unix: 1,
                closes_at_unix: 1,
            },
            ContactError::EmptyBudget,
        ];
        for (name, err) in names.iter().zip(&all) {
            assert_eq!(err.name(), *name);
            assert!(!err.to_string().is_empty(), "{name} has no Display");
        }
    }
}
