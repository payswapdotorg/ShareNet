//! # sharenet-developer-api — the hosted Developer API model layer (C2-005)
//!
//! Work item C2-005 (wave P1) of the ShareNet productization program
//! (`spec/product-console-plan.yaml`): the MODEL layer of the hosted
//! Developer API — the application registry, developer authentication and
//! credentials, the scope taxonomy and decision API, the webhook
//! registration/delivery model with SIGNED events, and the quota/rate-limit
//! policy model, per the normative developer contract
//! (`spec/developer-integration.yaml`).
//!
//! # What this crate OWNS
//!
//! Exactly the hosted-API ownership list of
//! `docs/tech-lead/SHARENET-CONSOLE-IMPLEMENTATION-HANDOFF.md`:
//! application registration, environments, credentials, scopes, webhook
//! registration and signed events, quotas, and evidence-reference-shaped
//! data (ids + typed records). Successor work items C2-006..C2-010 build on
//! these types.
//!
//! # What this crate NEVER OWNS (boundary laws L030/L031)
//!
//! Node private keys. Route/circuit authority. Raw packet forwarding.
//! ADCOS ConnectivityContract authority. Durable local node state. There
//! are NO protocol-core dependencies (the manifest depends on no
//! `sharenet-*` crate); the model operates on APPLICATION-SCOPED data only.
//! A hosted API call alone never turns a browser or phone into a ShareNet
//! data-plane node (L028). Deployment/serving of the hosted service is
//! C3-005 — this crate is pure model: no I/O, no wall clock (time is a
//! parameter), no transport, no randomness source (ids/nonces are minted
//! deterministically from the deployment seed).
//!
//! # The facade
//!
//! [`DeveloperApi`] composes the stores ([`app::AppRegistry`] is the root
//! truth — every other store consults it) and enforces the cross-cutting
//! laws:
//!
//! - **fail closed**: revoked apps/environments/credentials fail on every
//!   verification, decision and emission path, always from REGISTRY truth,
//!   never from caller claims;
//! - **app isolation**: app A can never read, act on, or verify against app
//!   B's registrations, webhooks, deliveries or credentials (cross-app ids
//!   are simply unknown — no oracle);
//! - **least privilege**: credential scope subsets are validated against the
//!   app/environment assignment at issue time and enforced at decision time;
//! - **explicit rotation**: bounded overlap windows, exact and testable.
//!
//! # Persistence
//!
//! The whole model state round-trips: [`DeveloperApi::snapshot`] /
//! [`DeveloperApi::restore`] (and the JSON forms) serialize every store
//! deterministically; restore re-validates ids, secrets and policies at
//! parse time (fail closed on corrupt snapshots). Durable persistence of
//! hosted state is C3-005's deployment concern; the model's contract is
//! exact round-trip fidelity.

#![forbid(unsafe_code)]

pub mod app;
pub mod credential;
pub mod ids;
pub mod quota;
pub mod scopes;
pub mod webhook;

pub use app::{AppProfile, AppRecord, AppRegistry, AppRegistryError, AppStatus, EnvironmentKind, EnvironmentRecord, EnvironmentStatus};
pub use credential::{
    AuthChallenge, AuthError, AuthenticatedIdentity, CredentialError, CredentialRecord, CredentialStatus, CredentialStore, DEFAULT_CHALLENGE_TTL_SECS,
};
pub use ids::{
    AppId, CredentialId, DeliveryId, EnvironmentId, EventId, IdError, IdKind, IdMint, NonceNamespace, RegistrySeed, WebhookId,
};
pub use quota::{QuotaDecision, QuotaEngine, QuotaError, QuotaPolicy};
pub use scopes::{
    decide_scope, Scope, ScopeContext, ScopeDecision, ScopeDenialReason, ScopeError, ScopeSet, ScopeStore,
};
pub use webhook::{
    canonical_json, sign_event_bytes, write_canonical_json, CanonicalValue, DeliveryOutcome, DeliveryRecord, DeliveryState, EmittedWebhookEvent, EventType, ReplayGuard, SignedEvent, WebhookError, WebhookRegistration, WebhookSecret, WebhookStatus, WebhookStore, DEFAULT_TIMESTAMP_TOLERANCE_SECS, MAX_DELIVERY_ATTEMPTS, WEBHOOK_ENVELOPE_PREFIX, WEBHOOK_SIGNATURE_SCHEME,
};

use serde::{Deserialize, Serialize};

/// The composed Developer API model (the facade).
#[derive(Clone, Serialize, Deserialize)]
pub struct DeveloperApi {
    apps: AppRegistry,
    credentials: CredentialStore,
    scopes: ScopeStore,
    webhooks: WebhookStore,
    quota: QuotaEngine,
}

impl DeveloperApi {
    /// A model with the fixed well-known TEST seed (deterministic ids) and
    /// the documented free-tier default quota policy.
    pub fn new() -> Self {
        DeveloperApi::with_seed(
            RegistrySeed::from_u128_pair(0x5a_e5, 0x11_aa),
            QuotaPolicy::FREE_TIER,
        )
    }

    /// A model with the deployment seed and default quota policy.
    pub fn with_seed(seed: RegistrySeed, default_quota: QuotaPolicy) -> Self {
        // Every store shares the deployment seed; id uniqueness holds because
        // each id KIND is minted by exactly one store (see ids.rs).
        DeveloperApi {
            apps: AppRegistry::with_seed(seed.clone()),
            credentials: CredentialStore::with_seed(seed.clone()),
            scopes: ScopeStore::new(),
            webhooks: WebhookStore::with_seed(seed),
            quota: QuotaEngine::new(default_quota),
        }
    }

    // -- store accessors (advanced/testing; the facade methods below are the
    //    primary surface) -----------------------------------------------

    pub fn apps(&self) -> &AppRegistry {
        &self.apps
    }

    pub fn credentials(&self) -> &CredentialStore {
        &self.credentials
    }

    pub fn scopes(&self) -> &ScopeStore {
        &self.scopes
    }

    pub fn webhooks(&self) -> &WebhookStore {
        &self.webhooks
    }

    pub fn quota(&self) -> &QuotaEngine {
        &self.quota
    }

    // -- application lifecycle -------------------------------------------

    /// `register_app` (facade): registry-issued stable app id.
    pub fn create_app(
        &mut self,
        name: &str,
        profiles: &[AppProfile],
        at: u64,
    ) -> Result<AppRecord, AppRegistryError> {
        self.apps.create_app(name, profiles, at)
    }

    /// `describe_app` (facade, app-scoped audit view — status included).
    pub fn describe_app(&self, app: &AppId) -> Result<AppRecord, AppRegistryError> {
        self.apps
            .app(app)
            .cloned()
            .ok_or_else(|| AppRegistryError::UnknownApp(app.clone()))
    }

    /// `create_environment` (facade).
    pub fn create_environment(
        &mut self,
        app: &AppId,
        kind: EnvironmentKind,
        at: u64,
    ) -> Result<EnvironmentRecord, AppRegistryError> {
        self.apps.create_environment(app, kind, at)
    }

    /// `revoke_app` (facade): the AUTHORITATIVE, terminal, everywhere-binding
    /// revocation — cascades to environments, and every verification,
    /// decision and emission path fails closed from this instant on.
    pub fn revoke_app(
        &mut self,
        app: &AppId,
        reason: &str,
        at: u64,
    ) -> Result<(), AppRegistryError> {
        self.apps.revoke_app(app, reason, at)
    }

    pub fn revoke_environment(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        reason: &str,
        at: u64,
    ) -> Result<(), AppRegistryError> {
        self.apps.revoke_environment(app, env, reason, at)
    }

    // -- scopes -----------------------------------------------------------

    /// `configure_allowed_scopes` (facade).
    pub fn assign_scopes(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        allowed: ScopeSet,
        at: u64,
    ) -> Result<(), ScopeError> {
        self.scopes.assign(&self.apps, app, env, allowed, at)
    }

    /// The scope-decision API (facade, total).
    pub fn decide_scope(
        &self,
        app: &AppId,
        env: &EnvironmentId,
        scope: Scope,
        credential: &CredentialId,
        at: u64,
    ) -> ScopeDecision {
        scopes::decide_scope(
            &self.apps,
            &self.credentials,
            &self.scopes,
            app,
            env,
            scope,
            ScopeContext { credential, at },
        )
    }

    // -- credentials + authentication -------------------------------------

    /// `issue_client_credentials` (facade): registers a PUBLIC key with its
    /// own least-privilege scope subset. The subset must be contained in the
    /// (app, environment) assignment — minting a credential with scopes the
    /// app was never assigned is refused here, not merely ineffective later.
    pub fn issue_credential(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        label: &str,
        public_key: &[u8; 32],
        scopes: ScopeSet,
        expires_at: Option<u64>,
        at: u64,
    ) -> Result<CredentialRecord, CredentialError> {
        match self.scopes.assignment(app, env) {
            Some(assignment) if scopes.is_subset_of(&assignment.allowed) => {}
            Some(assignment) => {
                return Err(CredentialError::ScopeSubsetViolation(format!(
                    "credential scopes must be a subset of the assignment for {app}/{env}; assignment: {}",
                    assignment.allowed
                )))
            }
            None => {
                return Err(CredentialError::ScopeSubsetViolation(format!(
                    "no scope assignment exists for {app}/{env} — configure_allowed_scopes first"
                )))
            }
        }
        self.credentials
            .issue(&self.apps, app, env, label, public_key, scopes, expires_at, at)
    }

    /// `rotate_credentials` (facade): bounded overlap window (`grace_secs`),
    /// `0` kills the old key at the rotation instant.
    pub fn rotate_credential(
        &mut self,
        credential: &CredentialId,
        new_public_key: &[u8; 32],
        grace_secs: u64,
        at: u64,
    ) -> Result<CredentialRecord, CredentialError> {
        self.credentials
            .rotate(&self.apps, credential, new_public_key, grace_secs, at)
    }

    pub fn revoke_credential(
        &mut self,
        credential: &CredentialId,
        reason: &str,
        at: u64,
    ) -> Result<(), CredentialError> {
        self.credentials.revoke(credential, reason, at)
    }

    /// Issue a single-use authentication challenge (facade).
    pub fn issue_challenge(
        &mut self,
        credential: &CredentialId,
        now: u64,
    ) -> Result<AuthChallenge, AuthError> {
        self.credentials.issue_challenge(&self.apps, credential, now)
    }

    /// The authentication verification API (facade, fail closed). The
    /// envelope a developer signs is
    /// [`CredentialStore::auth_envelope`].
    pub fn verify_authentication(
        &mut self,
        credential: &CredentialId,
        nonce: &[u8; 16],
        signature: &[u8; 64],
        now: u64,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        self.credentials
            .verify_authentication(&self.apps, credential, nonce, signature, now)
    }

    // -- webhooks -----------------------------------------------------------

    /// `register_webhooks` (facade).
    pub fn register_webhook(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        url: &str,
        event_types: std::collections::BTreeSet<EventType>,
        secret: WebhookSecret,
        at: u64,
    ) -> Result<WebhookRegistration, WebhookError> {
        self.webhooks.register(&self.apps, app, env, url, event_types, secret, at)
    }

    pub fn revoke_webhook(
        &mut self,
        webhook: &WebhookId,
        reason: &str,
        at: u64,
    ) -> Result<(), WebhookError> {
        self.webhooks.revoke(webhook, reason, at)
    }

    /// The app-scoped webhook list (facade): app A only ever sees its own.
    pub fn webhooks_for_app(&self, app: &AppId) -> Vec<WebhookRegistration> {
        self.webhooks
            .registrations_for_app(app)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Emit a typed application event (facade): one signed event + one
    /// Pending delivery record per ACTIVE subscribed webhook of (app,
    /// environment). This is the DEV-005/DEV-006/DEV-007 emission point.
    pub fn emit_event(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        event_type: EventType,
        payload: CanonicalValue,
        now: u64,
    ) -> Result<Vec<EmittedWebhookEvent>, WebhookError> {
        self.webhooks
            .emit_event(&self.apps, app, env, event_type, payload, now)
    }

    /// Verify a signed event under `app`'s context (facade, fail closed —
    /// the full documented order; see [`webhook`]).
    pub fn verify_event(
        &mut self,
        app: &AppId,
        signed: &SignedEvent,
        now: u64,
    ) -> Result<(), WebhookError> {
        self.webhooks.verify_event(&self.apps, app, signed, now)
    }

    /// Report a delivery outcome (facade — the hosted worker's callback).
    pub fn record_delivery_outcome(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        at: u64,
    ) -> Result<DeliveryRecord, WebhookError> {
        self.webhooks.record_outcome(delivery, outcome, at)
    }

    /// The app-scoped delivery list (facade): app A only ever sees its own.
    pub fn deliveries_for_app(&self, app: &AppId) -> Vec<DeliveryRecord> {
        self.webhooks
            .deliveries_for_app(app)
            .into_iter()
            .cloned()
            .collect()
    }

    // -- quotas --------------------------------------------------------------

    /// Set the per-(app, environment) quota policy override (facade).
    pub fn set_quota_policy(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        policy: QuotaPolicy,
    ) -> Result<(), QuotaError> {
        self.quota.set_policy(app, env, policy)
    }

    /// The pure over/under decision (facade — does not count).
    pub fn quota_evaluate(&self, app: &AppId, env: &EnvironmentId, at: u64) -> QuotaDecision {
        self.quota.evaluate(app, env, at)
    }

    /// Count one request against the policy (facade): the over/under
    /// decision, counting when allowed.
    pub fn quota_consume(&mut self, app: &AppId, env: &EnvironmentId, at: u64) -> QuotaDecision {
        self.quota.consume(app, env, at)
    }

    // -- persistence -----------------------------------------------------------

    /// A deep snapshot of the whole model state.
    pub fn snapshot(&self) -> DeveloperApi {
        self.clone()
    }

    /// Restore a model from a snapshot (validates on the way in: ids,
    /// secrets, policies all re-parse; corrupt fields fail closed).
    pub fn restore(snapshot: DeveloperApi) -> Self {
        snapshot
    }

    /// Snapshot to a JSON string (the model's persistence round-trip form).
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Restore from a JSON string (fail closed on any malformation).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// State hygiene for persistence: drop expired challenges and stale
    /// replay-guard entries (behavior-safe; see the pruning docs).
    pub fn prune(&mut self, now: u64) {
        self.credentials.prune_challenges(now);
        self.webhooks.prune(now);
    }
}

impl Default for DeveloperApi {
    fn default() -> Self {
        Self::new()
    }
}

/// Marker types/aliases the successor work items (C2-006..C2-010) build on.
///
/// `EvidenceReference` is the model's evidence-reference shape: a typed
/// pointer into registry truth (the exact record id + the record kind), the
/// ONLY evidence surface the hosted Developer API owns
/// (`spec/developer-integration.yaml`: "evidence references" — references,
/// not protocol evidence itself).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub app_id: AppId,
    pub kind: EvidenceKind,
    pub subject_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    App,
    Environment,
    Credential,
    Webhook,
    Event,
    Delivery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_rejects_credential_scopes_outside_the_assignment() {
        let mut api = DeveloperApi::new();
        let app = api.create_app("app", &[AppProfile::Participant], 1).unwrap().app_id.clone();
        let env = api.create_environment(&app, EnvironmentKind::Prod, 2).unwrap().environment_id.clone();
        let key = [1u8; 32];
        // No assignment yet: refused.
        assert!(matches!(
            api.issue_credential(&app, &env, "ci", &key, ScopeSet::parse(&["sessions:read"]).unwrap(), None, 3),
            Err(CredentialError::ScopeSubsetViolation(_))
        ));
        api.assign_scopes(
            &app,
            &env,
            ScopeSet::parse(&["sessions:read", "events:read"]).unwrap(),
            4,
        )
        .unwrap();
        // Subset: OK.
        assert!(api
            .issue_credential(&app, &env, "ci", &key, ScopeSet::parse(&["sessions:read"]).unwrap(), None, 5)
            .is_ok());
        // Superset: refused at issue time (least privilege is structural).
        assert!(matches!(
            api.issue_credential(&app, &env, "ci2", &key, ScopeSet::parse(&["sessions:read", "app:manage"]).unwrap(), None, 6),
            Err(CredentialError::ScopeSubsetViolation(_))
        ));
    }

    #[test]
    fn json_round_trip_preserves_behavioral_state() {
        let mut api = DeveloperApi::new();
        let app = api.create_app("roundtrip", &[AppProfile::Participant], 1).unwrap().app_id.clone();
        let env = api.create_environment(&app, EnvironmentKind::Prod, 2).unwrap().environment_id.clone();
        let json = api.to_json().unwrap();
        let restored = DeveloperApi::from_json(&json).unwrap();
        assert_eq!(restored.to_json().unwrap(), json, "byte-identical double round trip");
        // Behavior continues: the same app id is known and active.
        assert!(restored.apps().active_app(&app).is_ok());
        assert!(restored.apps().active_environment(&app, &env).is_ok());
        assert!(restored.webhooks_for_app(&app).is_empty());
    }

    #[test]
    fn corrupt_json_fails_closed() {
        assert!(DeveloperApi::from_json("not json").is_err());
        assert!(DeveloperApi::from_json("{}").is_err());
        let mut api = DeveloperApi::new();
        api.create_app("x", &[AppProfile::Consumer], 1).unwrap();
        let json = api.to_json().unwrap();
        // Tamper: a malformed id inside the snapshot is rejected at restore.
        let tampered = json.replace("app_", "app_X");
        assert!(DeveloperApi::from_json(&tampered).is_err());
    }
}
