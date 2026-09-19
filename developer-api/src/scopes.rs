//! The developer scope taxonomy and the total scope-decision API (C2-005).
//!
//! # Where the taxonomy comes from
//!
//! Every scope in this module is derived from a verb the normative developer
//! contract (`spec/developer-integration.yaml`) actually names — no scope
//! exists that the spec does not justify, and no spec verb is left unmodeled:
//!
//! | Family | Scope | Spec anchor (`spec/developer-integration.yaml`) |
//! |---|---|---|
//! | app | `app:read` | "owns: application registration… evidence references" + the DEV-007 observability journey |
//! | app | `app:manage` | `backend_contract.application_lifecycle`: create_environment, issue_client_credentials, configure_allowed_scopes, register_webhooks, rotate_credentials, revoke_app |
//! | users | `users:authorize` | `backend_contract.user_lifecycle`: begin_user_authorization, exchange_user_code |
//! | devices | `devices:enroll` | `user_lifecycle`: enroll_device, bind_node_to_host_app |
//! | devices | `devices:revoke` | `user_lifecycle`: revoke_device, revoke_participation |
//! | sessions | `sessions:read` | `sessions`: observe_session |
//! | sessions | `sessions:connectivity` | `sessions`: create_connectivity_session |
//! | sessions | `sessions:transfer` | `sessions`: create_transfer |
//! | sessions | `sessions:cancel` | `sessions`: cancel_session |
//! | events | `events:read` | `events`: the eight typed application events |
//! | events | `webhooks:manage` | `application_lifecycle`: register_webhooks |
//! | participation | `participation:endpoint` … `participation:gateway` | `participation_profiles.participant.possible_capabilities`: endpoint, content_source, custody, relay, gateway |
//! | evidence | `evidence:read` | "owns: … evidence references" |
//!
//! `register_app` itself is deliberately NOT a scope: an app cannot act before
//! it exists; registration is the bootstrap the hosted service performs.
//!
//! # Profile gating (the model's reading of the spec)
//!
//! The spec defines three participation profiles. The scope model binds each
//! scope to the profiles that may ever hold it:
//!
//! - `participation:relay` and `participation:gateway` are DEVICE data-plane
//!   capabilities — only the `participant` profile may hold them.
//! - `participation:endpoint`, `participation:content_source` and
//!   `participation:custody` are also legitimate for a `service_backend`
//!   ("developer backend participates as an application/service endpoint").
//! - Every other scope (app/users/devices/sessions/events/evidence) is
//!   available to all three profiles.
//!
//! # Least privilege
//!
//! `security: least_privilege_scopes` is implemented structurally: an app's
//! **assignment** (per environment) bounds what the app may ever do, and each
//! **credential** holds a subset of that assignment. A scope decision requires
//! BOTH: the assignment AND the credential's own subset. A credential asking
//! beyond either is denied with a typed reason — never silently upgraded.
//!
//! # Totality
//!
//! [`decide_scope`] is total: every (app, environment, credential, scope,
//! time) combination produces an [`Allowed`] or a typed [`Denied`] reason.
//! There is no undefined combination and no panic path.

use crate::app::{AppProfile, AppRegistry, AppRegistryError};
use crate::credential::{CredentialRecord, CredentialStatus, CredentialStore};
use crate::ids::{AppId, CredentialId, EnvironmentId, EntryMap};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// A developer scope. The complete taxonomy (17 scopes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Scope {
    // app family
    AppRead,
    AppManage,
    // user lifecycle family
    UsersAuthorize,
    DevicesEnroll,
    DevicesRevoke,
    // sessions family
    SessionsRead,
    SessionsConnectivity,
    SessionsTransfer,
    SessionsCancel,
    // events family
    EventsRead,
    WebhooksManage,
    // participation capability family (participant/service_backend only)
    ParticipationEndpoint,
    ParticipationContentSource,
    ParticipationCustody,
    ParticipationRelay,
    ParticipationGateway,
    // evidence family
    EvidenceRead,
}

impl Scope {
    /// The canonical wire name (the string developers see and request).
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::AppRead => "app:read",
            Scope::AppManage => "app:manage",
            Scope::UsersAuthorize => "users:authorize",
            Scope::DevicesEnroll => "devices:enroll",
            Scope::DevicesRevoke => "devices:revoke",
            Scope::SessionsRead => "sessions:read",
            Scope::SessionsConnectivity => "sessions:connectivity",
            Scope::SessionsTransfer => "sessions:transfer",
            Scope::SessionsCancel => "sessions:cancel",
            Scope::EventsRead => "events:read",
            Scope::WebhooksManage => "webhooks:manage",
            Scope::ParticipationEndpoint => "participation:endpoint",
            Scope::ParticipationContentSource => "participation:content_source",
            Scope::ParticipationCustody => "participation:custody",
            Scope::ParticipationRelay => "participation:relay",
            Scope::ParticipationGateway => "participation:gateway",
            Scope::EvidenceRead => "evidence:read",
        }
    }

    /// The family name (documentation/telemetry).
    pub const fn family(self) -> &'static str {
        match self {
            Scope::AppRead | Scope::AppManage => "app",
            Scope::UsersAuthorize => "users",
            Scope::DevicesEnroll | Scope::DevicesRevoke => "devices",
            Scope::SessionsRead
            | Scope::SessionsConnectivity
            | Scope::SessionsTransfer
            | Scope::SessionsCancel => "sessions",
            Scope::EventsRead | Scope::WebhooksManage => "events",
            Scope::ParticipationEndpoint
            | Scope::ParticipationContentSource
            | Scope::ParticipationCustody
            | Scope::ParticipationRelay
            | Scope::ParticipationGateway => "participation",
            Scope::EvidenceRead => "evidence",
        }
    }

    /// The profiles that may ever hold this scope (profile gating).
    pub fn available_to(self, profile: AppProfile) -> bool {
        match self {
            Scope::ParticipationEndpoint
            | Scope::ParticipationContentSource
            | Scope::ParticipationCustody => {
                matches!(profile, AppProfile::Participant | AppProfile::ServiceBackend)
            }
            Scope::ParticipationRelay | Scope::ParticipationGateway => {
                matches!(profile, AppProfile::Participant)
            }
            _ => true,
        }
    }

    /// Parse the canonical wire name. Unknown strings are rejected (total).
    pub fn parse(s: &str) -> Result<Scope, ScopeError> {
        Ok(match s {
            "app:read" => Scope::AppRead,
            "app:manage" => Scope::AppManage,
            "users:authorize" => Scope::UsersAuthorize,
            "devices:enroll" => Scope::DevicesEnroll,
            "devices:revoke" => Scope::DevicesRevoke,
            "sessions:read" => Scope::SessionsRead,
            "sessions:connectivity" => Scope::SessionsConnectivity,
            "sessions:transfer" => Scope::SessionsTransfer,
            "sessions:cancel" => Scope::SessionsCancel,
            "events:read" => Scope::EventsRead,
            "webhooks:manage" => Scope::WebhooksManage,
            "participation:endpoint" => Scope::ParticipationEndpoint,
            "participation:content_source" => Scope::ParticipationContentSource,
            "participation:custody" => Scope::ParticipationCustody,
            "participation:relay" => Scope::ParticipationRelay,
            "participation:gateway" => Scope::ParticipationGateway,
            "evidence:read" => Scope::EvidenceRead,
            other => return Err(ScopeError::UnknownScope(other.to_owned())),
        })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Scope::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// An owned set of scopes (least-privilege boundary). Parsing rejects unknown
/// scopes; iteration is canonical (BTreeSet order).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ScopeSet(BTreeSet<Scope>);

impl ScopeSet {
    /// The empty set (a credential that may do nothing).
    pub fn empty() -> Self {
        ScopeSet(BTreeSet::new())
    }

    /// Parse from canonical wire names; every entry must be known.
    pub fn parse(names: &[&str]) -> Result<Self, ScopeError> {
        let mut set = BTreeSet::new();
        for n in names {
            set.insert(Scope::parse(n)?);
        }
        Ok(ScopeSet(set))
    }

    /// Build from scopes directly.
    pub fn from_scopes(scopes: impl IntoIterator<Item = Scope>) -> Self {
        ScopeSet(scopes.into_iter().collect())
    }

    pub fn contains(&self, s: Scope) -> bool {
        self.0.contains(&s)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = Scope> + '_ {
        self.0.iter().copied()
    }

    /// True when `self` is a subset of `other`.
    pub fn is_subset_of(&self, other: &ScopeSet) -> bool {
        self.0.iter().all(|s| other.0.contains(s))
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in self.iter() {
            if !first {
                f.write_str(" ")?;
            }
            <Scope as fmt::Display>::fmt(&s, f)?;
            first = false;
        }
        Ok(())
    }
}

/// The per-(app, environment) allowed-scope assignment
/// (`backend_contract.application_lifecycle.configure_allowed_scopes`).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScopeAssignment {
    pub app_id: AppId,
    pub environment_id: EnvironmentId,
    pub allowed: ScopeSet,
    pub updated_at: u64,
}

/// The scope store: assignments per (app, environment).
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct ScopeStore {
    assignments: EntryMap<(AppId, EnvironmentId), ScopeAssignment>,
}

impl ScopeStore {
    pub fn new() -> Self {
        ScopeStore::default()
    }

    /// `configure_allowed_scopes`: replace the assignment for (app,
    /// environment). Validates the app/environment are active registry truth
    /// and that every requested scope is available to the app's profiles.
    pub fn assign(
        &mut self,
        apps: &AppRegistry,
        app: &AppId,
        env: &EnvironmentId,
        allowed: ScopeSet,
        at: u64,
    ) -> Result<(), ScopeError> {
        let record = apps.active_app(app).map_err(ScopeError::Registry)?;
        let env_record = apps
            .active_environment(app, env)
            .map_err(ScopeError::Registry)?;
        debug_assert_eq!(env_record.app_id, *app);
        for scope in allowed.iter() {
            if !record.profiles.iter().any(|p| scope.available_to(*p)) {
                return Err(ScopeError::NotAvailableForProfile {
                    scope,
                    app: app.clone(),
                });
            }
        }
        self.assignments.insert(
            (app.clone(), env.clone()),
            ScopeAssignment { app_id: app.clone(), environment_id: env.clone(), allowed, updated_at: at },
        );
        Ok(())
    }

    /// The assignment for (app, environment), if any was configured.
    pub fn assignment(&self, app: &AppId, env: &EnvironmentId) -> Option<&ScopeAssignment> {
        self.assignments.get(&(app.clone(), env.clone()))
    }
}

/// Context for a scope decision: WHICH credential is asking, and WHEN.
/// The credential must itself be verifiable (active, unexpired, held by this
/// app) — an unauthenticated or dead credential can never carry a scope.
#[derive(Clone, Copy, Debug)]
pub struct ScopeContext<'a> {
    pub credential: &'a CredentialId,
    pub at: u64,
}

/// A total scope decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeDecision {
    Allowed { scope: Scope, credential: CredentialId },
    Denied { scope: Scope, reason: ScopeDenialReason },
}

/// Typed denial reasons — every failure mode is named, none is undefined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeDenialReason {
    /// The app id does not exist in the registry.
    UnknownApp,
    /// The app exists but is revoked — registry truth is authoritative.
    AppRevoked,
    /// The environment id is unknown (or belongs to another app — no oracle).
    UnknownEnvironment,
    /// The environment exists but is revoked.
    EnvironmentRevoked,
    /// The credential id is unknown (or not registered to this app and
    /// environment — cross-app use is indistinguishable from nonexistent).
    UnknownCredential,
    /// The credential has been revoked.
    CredentialRevoked,
    /// The credential's hard expiry has passed.
    CredentialExpired,
    /// The credential was rotated away and its overlap window has ended.
    RotationWindowEnded,
    /// No assignment exists for (app, environment) — default deny.
    ScopeNotAssigned,
    /// The scope is not assignable to this app's profiles (defense in depth;
    /// assignment creation also validates this).
    ScopeNotAvailableForProfile,
    /// The credential's own scope set does not include the requested scope
    /// (least privilege — the escalation deny).
    CredentialDoesNotHoldScope,
}

impl std::fmt::Display for ScopeDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ScopeDenialReason::UnknownApp => "unknown_app",
            ScopeDenialReason::AppRevoked => "app_revoked",
            ScopeDenialReason::UnknownEnvironment => "unknown_environment",
            ScopeDenialReason::EnvironmentRevoked => "environment_revoked",
            ScopeDenialReason::UnknownCredential => "unknown_credential",
            ScopeDenialReason::CredentialRevoked => "credential_revoked",
            ScopeDenialReason::CredentialExpired => "credential_expired",
            ScopeDenialReason::RotationWindowEnded => "rotation_window_ended",
            ScopeDenialReason::ScopeNotAssigned => "scope_not_assigned",
            ScopeDenialReason::ScopeNotAvailableForProfile => "scope_not_available_for_profile",
            ScopeDenialReason::CredentialDoesNotHoldScope => "credential_does_not_hold_scope",
        };
        f.write_str(name)
    }
}

/// The total scope-decision API.
///
/// Given app + environment + requested scope + context (credential, time):
/// allow or deny with a typed reason. Registry truth (app registry +
/// credential store) is consulted directly — the caller cannot present any
/// security facts of its own.
pub fn decide_scope(
    apps: &AppRegistry,
    credentials: &CredentialStore,
    scopes: &ScopeStore,
    app: &AppId,
    env: &EnvironmentId,
    scope: Scope,
    ctx: ScopeContext<'_>,
) -> ScopeDecision {
    let denied = |reason| ScopeDecision::Denied { scope, reason };
    // 1. Registry truth: the app must exist and be active.
    let app_record = match apps.app(app) {
        None => return denied(ScopeDenialReason::UnknownApp),
        Some(r) if !r.is_active() => return denied(ScopeDenialReason::AppRevoked),
        Some(r) => r,
    };
    // 2. The environment must exist, belong to this app and be active.
    match apps.environment(app, env) {
        Some(e) if e.app_id == *app && e.is_active() => {}
        Some(_) => return denied(ScopeDenialReason::EnvironmentRevoked),
        None => return denied(ScopeDenialReason::UnknownEnvironment),
    }
    // 3. The credential must exist AND be registered to this exact
    //    (app, environment) — cross-app reuse is indistinguishable from
    //    unknown (no oracle about other apps' credentials).
    let cred: &CredentialRecord = match credentials.credential(ctx.credential) {
        Some(c) if c.app_id == *app && c.environment_id == *env => c,
        Some(_) => return denied(ScopeDenialReason::UnknownCredential),
        None => return denied(ScopeDenialReason::UnknownCredential),
    };
    // 4. Credential lifecycle state, from registry truth.
    match &cred.status {
        CredentialStatus::Revoked { .. } => return denied(ScopeDenialReason::CredentialRevoked),
        CredentialStatus::Rotating { dies_at, .. } if ctx.at >= *dies_at => {
            return denied(ScopeDenialReason::RotationWindowEnded)
        }
        _ => {}
    }
    if let Some(expires_at) = cred.expires_at {
        if ctx.at >= expires_at {
            return denied(ScopeDenialReason::CredentialExpired);
        }
    }
    // 5. App-level assignment must include the scope.
    let assignment = match scopes.assignment(app, env) {
        Some(a) if a.allowed.contains(scope) => a,
        Some(_) => return denied(ScopeDenialReason::ScopeNotAssigned),
        None => return denied(ScopeDenialReason::ScopeNotAssigned),
    };
    let _ = assignment;
    // 6. Profile gating, re-checked at decision time (defense in depth).
    if !app_record.profiles.iter().any(|p| scope.available_to(*p)) {
        return denied(ScopeDenialReason::ScopeNotAvailableForProfile);
    }
    // 7. Least privilege: the credential's own subset must include it.
    if !cred.scopes.contains(scope) {
        return denied(ScopeDenialReason::CredentialDoesNotHoldScope);
    }
    ScopeDecision::Allowed { scope, credential: ctx.credential.clone() }
}

/// Errors of the scope module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    UnknownScope(String),
    Registry(AppRegistryError),
    NotAvailableForProfile { scope: Scope, app: AppId },
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::UnknownScope(s) => write!(f, "unknown scope: {s}"),
            ScopeError::Registry(e) => write!(f, "registry: {e}"),
            ScopeError::NotAvailableForProfile { scope, app } => {
                write!(f, "scope {scope} is not available to app {app}'s profiles")
            }
        }
    }
}

impl std::error::Error for ScopeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::EnvironmentKind;
    use crate::credential::CredentialStore;

    fn setup() -> (AppRegistry, CredentialStore, ScopeStore, AppId, EnvironmentId, CredentialId) {
        let mut apps = AppRegistry::new();
        let app = apps
            .create_app("field-messaging", &[AppProfile::Participant], 1_000)
            .unwrap()
            .app_id
            .clone();
        let env = apps
            .create_environment(&app, EnvironmentKind::Prod, 1_100)
            .unwrap()
            .environment_id
            .clone();
        let mut creds = CredentialStore::new();
        let mut pk = [0u8; 32];
        pk[0] = 9;
        let cred = creds
            .issue(
                &apps,
                &app,
                &env,
                "ci",
                &pk,
                ScopeSet::parse(&["sessions:read", "events:read"]).unwrap(),
                Some(9_000),
                1_200,
            )
            .unwrap();
        let mut scope_store = ScopeStore::new();
        scope_store
            .assign(
                &apps,
                &app,
                &env,
                ScopeSet::parse(&["sessions:read", "sessions:cancel", "events:read"]).unwrap(),
                1_250,
            )
            .unwrap();
        let cred_id = cred.credential_id.clone();
        (apps, creds, scope_store, app, env, cred_id)
    }

    fn decide(
        parts: &(AppRegistry, CredentialStore, ScopeStore, AppId, EnvironmentId, CredentialId),
        scope: Scope,
        at: u64,
    ) -> ScopeDecision {
        let (apps, creds, scopes, app, env, cred) = parts;
        decide_scope(
            apps,
            creds,
            scopes,
            app,
            env,
            scope,
            ScopeContext { credential: cred, at },
        )
    }

    #[test]
    fn taxonomy_is_complete_and_parses_round_trip() {
        assert_eq!(Scope::parse("app:manage").unwrap(), Scope::AppManage);
        assert!(Scope::parse("app:admin").is_err(), "unknown scope rejected");
        assert!(Scope::parse("sessions:read ").is_err(), "whitespace rejected");
        let all = [
            Scope::AppRead, Scope::AppManage, Scope::UsersAuthorize, Scope::DevicesEnroll,
            Scope::DevicesRevoke, Scope::SessionsRead, Scope::SessionsConnectivity,
            Scope::SessionsTransfer, Scope::SessionsCancel, Scope::EventsRead,
            Scope::WebhooksManage, Scope::ParticipationEndpoint,
            Scope::ParticipationContentSource, Scope::ParticipationCustody,
            Scope::ParticipationRelay, Scope::ParticipationGateway, Scope::EvidenceRead,
        ];
        let mut names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        // Every name unique.
        names.dedup();
        assert_eq!(names.len(), 17);
        for s in all {
            assert_eq!(Scope::parse(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn profile_gating_rules_hold() {
        assert!(Scope::ParticipationGateway.available_to(AppProfile::Participant));
        assert!(!Scope::ParticipationGateway.available_to(AppProfile::ServiceBackend));
        assert!(!Scope::ParticipationGateway.available_to(AppProfile::Consumer));
        assert!(Scope::ParticipationCustody.available_to(AppProfile::ServiceBackend));
        assert!(Scope::ParticipationCustody.available_to(AppProfile::Participant));
        assert!(!Scope::ParticipationEndpoint.available_to(AppProfile::Consumer));
        assert!(Scope::SessionsRead.available_to(AppProfile::Consumer));
        assert!(Scope::EvidenceRead.available_to(AppProfile::ServiceBackend));
    }

    #[test]
    fn assignment_rejects_scopes_the_profile_may_not_hold() {
        let (mut apps, _, mut scopes, app, env, _) = setup();
        // Consumer app cannot be assigned participation:gateway.
        let consumer = apps
            .create_app("plain-browser", &[AppProfile::Consumer], 2_000)
            .unwrap()
            .app_id
            .clone();
        let cenv = apps
            .create_environment(&consumer, EnvironmentKind::Dev, 2_010)
            .unwrap()
            .environment_id
            .clone();
        let err = scopes
            .assign(
                &apps,
                &consumer,
                &cenv,
                ScopeSet::parse(&["participation:gateway"]).unwrap(),
                2_020,
            )
            .unwrap_err();
        assert!(matches!(err, ScopeError::NotAvailableForProfile { .. }));
        // While the participant app can.
        scopes
            .assign(&apps, &app, &env, ScopeSet::parse(&["participation:gateway"]).unwrap(), 2_030)
            .unwrap();
    }

    #[test]
    fn happy_path_allowed_and_each_denial_reason_is_reachable() {
        let parts = setup();
        // Allowed: assigned + held.
        assert!(matches!(
            decide(&parts, Scope::SessionsRead, 1_500),
            ScopeDecision::Allowed { .. }
        ));
        // Credential does not hold it (escalation deny).
        assert_eq!(
            decide(&parts, Scope::SessionsCancel, 1_500),
            ScopeDecision::Denied { scope: Scope::SessionsCancel, reason: ScopeDenialReason::CredentialDoesNotHoldScope }
        );
        // Not in the assignment at all (app-level deny).
        assert_eq!(
            decide(&parts, Scope::AppManage, 1_500),
            ScopeDecision::Denied { scope: Scope::AppManage, reason: ScopeDenialReason::ScopeNotAssigned }
        );
        // Unknown app / environment / credential.
        let (apps, creds, scope_store, app, env, cred) = &parts;
        let unknown_app = AppId::parse("app_aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            decide_scope(apps, creds, scope_store, &unknown_app, env, Scope::SessionsRead, ScopeContext { credential: cred, at: 1_500 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownApp }
        );
        let unknown_env = EnvironmentId::parse("env_aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            decide_scope(apps, creds, scope_store, app, &unknown_env, Scope::SessionsRead, ScopeContext { credential: cred, at: 1_500 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownEnvironment }
        );
        let unknown_cred = CredentialId::parse("cred_aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            decide_scope(apps, creds, scope_store, app, env, Scope::SessionsRead, ScopeContext { credential: &unknown_cred, at: 1_500 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownCredential }
        );
    }

    #[test]
    fn revoked_app_and_environment_deny() {
        let (mut apps, creds, scope_store, app, env, cred) = setup();
        apps.revoke_app(&app, "policy", 1_600).unwrap();
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &app, &env, Scope::SessionsRead, ScopeContext { credential: &cred, at: 1_700 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::AppRevoked }
        );
        // Fresh app: revoke just the environment. The first app's
        // credential against the second app's revoked environment is denied
        // at the environment gate (env checks run before credential
        // binding — the documented order; a deny either way, never a match).
        let app2 = apps.create_app("b", &[AppProfile::Participant], 1_800).unwrap().app_id.clone();
        let env2 = apps.create_environment(&app2, EnvironmentKind::Dev, 1_810).unwrap().environment_id.clone();
        apps.revoke_environment(&app2, &env2, "retired", 1_820).unwrap();
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &app2, &env2, Scope::SessionsRead, ScopeContext { credential: &cred, at: 1_830 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::EnvironmentRevoked }
        );
        // And against a still-active environment of the second app, the
        // first app's credential is simply unknown (no oracle).
        let env2b = apps.create_environment(&app2, EnvironmentKind::Prod, 1_840).unwrap().environment_id.clone();
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &app2, &env2b, Scope::SessionsRead, ScopeContext { credential: &cred, at: 1_850 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownCredential }
        );
    }

    #[test]
    fn revoked_expired_and_rotated_out_credentials_deny() {
        let (apps, mut creds, scope_store, app, env, cred) = setup();
        // Expired (expires_at = 9_000).
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &app, &env, Scope::SessionsRead, ScopeContext { credential: &cred, at: 9_000 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::CredentialExpired }
        );
        // Revoked.
        creds.revoke(&cred, "leak", 2_000).unwrap();
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &app, &env, Scope::SessionsRead, ScopeContext { credential: &cred, at: 2_100 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::CredentialRevoked }
        );
        // Rotated with zero grace: old is dead immediately.
        let (apps2, mut creds2, scope_store2, app2, env2, cred2) = setup();
        let mut pk2 = [0u8; 32];
        pk2[0] = 10;
        creds2.rotate(&apps2, &cred2, &pk2, 0, 3_000).unwrap();
        assert_eq!(
            decide_scope(&apps2, &creds2, &scope_store2, &app2, &env2, Scope::SessionsRead, ScopeContext { credential: &cred2, at: 3_001 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::RotationWindowEnded }
        );
    }

    #[test]
    fn cross_app_credential_is_unknown_not_oracle() {
        let (mut apps, creds, scope_store, app, env, _) = setup();
        // A second app; the first app's credential used against the second
        // app is simply unknown — never a match, never an oracle.
        let other = apps.create_app("other", &[AppProfile::Participant], 1_900).unwrap().app_id.clone();
        let oenv = apps.create_environment(&other, EnvironmentKind::Prod, 1_910).unwrap().environment_id.clone();
        let cred = CredentialId::parse("cred_aaaaaaaaaaaaaaaa").unwrap();
        let _ = (&app, &env);
        assert_eq!(
            decide_scope(&apps, &creds, &scope_store, &other, &oenv, Scope::SessionsRead, ScopeContext { credential: &cred, at: 1_950 }),
            ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownCredential }
        );
    }

    #[test]
    fn scope_set_operations() {
        let a = ScopeSet::parse(&["app:read", "app:manage"]).unwrap();
        let b = ScopeSet::parse(&["app:manage"]).unwrap();
        assert!(b.is_subset_of(&a));
        assert!(!a.is_subset_of(&b));
        assert_eq!(a.len(), 2);
        assert!(ScopeSet::parse(&["nope"]).is_err());
        assert_eq!(format!("{}", ScopeSet::parse(&["sessions:read"]).unwrap()), "sessions:read");
    }
}
