//! Opaque capability references — the ONLY durable thing ShareNet holds about
//! ADCOS-managed objects.
//!
//! Per `spec/integrations/adcos.md`: ShareNet stores a
//! `ConnectivityContractRef` (plus optional lease/reference data); per
//! architecture lock L005, "`ConnectivityContract` is an opaque external
//! authority represented inside ShareNet by a reference/projection".
//!
//! # NOT wire objects
//!
//! These are boundary-layer handles, deliberately NOT protocol wire objects:
//!
//! - no canonical CBOR encoding (ShareNet's canonical CBOR profile belongs to
//!   the protocol core, which this crate must not depend on);
//! - no signatures and no derivation — the bytes are exactly whatever the
//!   provider (or the test fake) assigned;
//! - **nobody may parse these bytes**. They are compared, stored and echoed,
//!   nothing more. The fake provider's ids are structured for debuggability
//!   (see `memory`), which a REAL provider's ids are not — treat both as
//!   opaque.
//!
//! Each reference is 32 opaque bytes plus a small typed [`RefKind`] tag. The
//! kind makes raw-byte reconstruction safe: [`ConnectivityContractRef::from_parts`]
//! refuses a kind mismatch, so a persisted offer id can never be resurrected
//! as a contract id (the seam the future R5-002 ADCOS client and R5-003
//! projection store will use when references arrive as raw bytes).

use core::fmt;

use crate::error::PortError;

/// Byte length of every opaque reference id.
pub const REF_ID_LEN: usize = 32;

/// What kind of ADCOS object a reference points at.
///
/// Kept as runtime data (not just the Rust type) so references reconstructed
/// from raw bytes — the seam the future ADCOS client (R5-002) and contract
/// projection store (R5-003) use — can be validated against the type they are
/// being fed into. Architecture §6 also names `ConnectivityLeaseRef`; leases
/// are future scope and will extend this enum in a versioned way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    /// Points at a connectivity intent (`createIntent` output).
    Intent,
    /// Points at a provider offer (`discoverOffers` output).
    Offer,
    /// Points at an ADCOS `ConnectivityContract` (`acceptOffer` output).
    Contract,
}

impl RefKind {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            RefKind::Intent => "intent",
            RefKind::Offer => "offer",
            RefKind::Contract => "contract",
        }
    }

    /// Parse from the machine name (the raw-byte reconstruction seam).
    pub fn from_name(name: &str) -> Option<RefKind> {
        match name {
            "intent" => Some(RefKind::Intent),
            "offer" => Some(RefKind::Offer),
            "contract" => Some(RefKind::Contract),
            _ => None,
        }
    }
}

impl fmt::Display for RefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lowercase hex (private helper; the same shape the protocol core uses).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

macro_rules! opaque_ref_type {
    ($name:ident, $kind:expr, $doc:expr) => {
        #[doc = $doc]
        ///
        /// Opaque: 32 provider-assigned bytes plus the [`RefKind`] tag. NOT a
        /// wire object — no canonical encoding, no signature, and the bytes
        /// must never be parsed.
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            kind: RefKind,
            id: [u8; REF_ID_LEN],
        }

        impl $name {
            /// Wrap an opaque 32-byte provider-assigned id, tagging it with
            /// this type's kind.
            pub fn from_id(id: [u8; REF_ID_LEN]) -> Self {
                Self { kind: $kind, id }
            }

            /// Rebuild from raw parts, validating the kind tag.
            ///
            /// This is the seam for references that arrive as raw bytes (a
            /// future projection store or the R5-002 ADCOS client): a kind
            /// mismatch is refused instead of silently re-typed.
            pub fn from_parts(
                kind: RefKind,
                id: [u8; REF_ID_LEN],
            ) -> Result<Self, PortError> {
                if kind != $kind {
                    return Err(PortError::RefKindMismatch {
                        expected: $kind,
                        found: kind,
                    });
                }
                Ok(Self { kind, id })
            }

            /// The object kind this reference points at.
            pub fn kind(&self) -> RefKind {
                self.kind
            }

            /// The raw 32 opaque bytes (do NOT parse these).
            pub fn id(&self) -> &[u8; REF_ID_LEN] {
                &self.id
            }

            /// Lowercase hex of the id (debugging/logging only).
            pub fn to_hex(&self) -> String {
                hex(&self.id)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }
    };
}

opaque_ref_type!(
    ConnectivityIntentRef,
    RefKind::Intent,
    "Opaque reference to an ADCOS connectivity intent — the `createIntent(requirement)` output."
);

opaque_ref_type!(
    ConnectivityOfferRef,
    RefKind::Offer,
    "Opaque reference to a provider offer — one `discoverOffers(intent)` output element."
);

opaque_ref_type!(
    ConnectivityContractRef,
    RefKind::Contract,
    "Opaque reference to an ADCOS `ConnectivityContract` — the `acceptOffer(intent, offer)` output.\n\nThe `ConnectivityContract` itself is ADCOS-owned canonical state; ShareNet holds only this reference and a local read-only projection (see `projection::ConnectivityContractProjection`). There is no second source of truth."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_carry_their_typed_kind() {
        let id = [0xABu8; REF_ID_LEN];
        assert_eq!(ConnectivityIntentRef::from_id(id).kind(), RefKind::Intent);
        assert_eq!(ConnectivityOfferRef::from_id(id).kind(), RefKind::Offer);
        assert_eq!(ConnectivityContractRef::from_id(id).kind(), RefKind::Contract);
    }

    #[test]
    fn from_parts_rejects_kind_mismatches() {
        let id = [0x01u8; REF_ID_LEN];
        // An offer id cannot be resurrected as a contract id...
        assert_eq!(
            ConnectivityContractRef::from_parts(RefKind::Offer, id),
            Err(PortError::RefKindMismatch {
                expected: RefKind::Contract,
                found: RefKind::Offer,
            })
        );
        // ...and an intent id cannot be resurrected as an offer id.
        assert_eq!(
            ConnectivityOfferRef::from_parts(RefKind::Intent, id),
            Err(PortError::RefKindMismatch {
                expected: RefKind::Offer,
                found: RefKind::Intent,
            })
        );
        // The matching kind round-trips.
        let contract = ConnectivityContractRef::from_parts(RefKind::Contract, id).unwrap();
        assert_eq!(contract.id(), &id);
        assert_eq!(contract.kind(), RefKind::Contract);
    }

    #[test]
    fn hex_and_debug_are_stable() {
        let ref_ = ConnectivityContractRef::from_id([0u8; REF_ID_LEN]);
        assert_eq!(ref_.to_hex().len(), 64);
        assert!(ref_.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
        let dbg = format!("{ref_:?}");
        assert!(dbg.starts_with("ConnectivityContractRef(") && dbg.ends_with(')'));
        assert_eq!(RefKind::from_name("offer"), Some(RefKind::Offer));
        assert_eq!(RefKind::from_name("bogus"), None);
    }
}
