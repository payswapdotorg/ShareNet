//! The application registry — the root truth of the hosted Developer API
//! (C2-005, `backend_contract.application_lifecycle`).
//!
//! # Registry truth
//!
//! The registry is THE truth for an application's existence. Every other
//! subsystem (credentials, scopes, webhooks, quotas) consults it through
//! `active_app` / `active_environment` — no caller-supplied booleans, ever.
//! **Revocation is authoritative everywhere**: a revoked app (or environment)
//! fails closed on every verification, decision and emission path, regardless
//! of any other state.
//!
//! # Environments
//!
//! Per `spec/developer-integration.yaml` (`owns: environments`,
//! `create_environment`), an app has environments. The productization model
//! pins the environment kinds to `dev`, `staging` and `prod`; at most one
//! environment of each kind exists per app (`DuplicateEnvironment`), so an
//! (app, kind) pair names at most one environment and revocation is never
//! ambiguous. Environment ids are registry-issued and stable; the KIND is the
//! human-facing label, the ID is the truth.
//!
//! # Boundaries (what this registry is NOT)
//!
//! Application-scoped control-plane data only. No node private keys, no
//! route/circuit authority, no raw packet forwarding, no ConnectivityContract
//! authority, no durable node state (architecture locks L030/L031 and the W2
//! hosted-API ownership list).

use crate::ids::{AppId, EnvironmentId, IdMint, RegistrySeed};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The environment kinds of the productization model (`dev`/`staging`/`prod`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentKind {
    Dev,
    Staging,
    Prod,
}

impl EnvironmentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnvironmentKind::Dev => "dev",
            EnvironmentKind::Staging => "staging",
            EnvironmentKind::Prod => "prod",
        }
    }

    pub fn parse(s: &str) -> Result<Self, AppRegistryError> {
        match s {
            "dev" => Ok(EnvironmentKind::Dev),
            "staging" => Ok(EnvironmentKind::Staging),
            "prod" => Ok(EnvironmentKind::Prod),
            other => Err(AppRegistryError::UnknownEnvironmentKind(other.to_owned())),
        }
    }
}

impl fmt::Display for EnvironmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The participation profiles of `spec/developer-integration.yaml`
/// (`participation_profiles`: consumer / participant / service_backend).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppProfile {
    /// Uses ShareNet to obtain resilient connectivity/content.
    Consumer,
    /// The host app/device opts into useful ShareNet participation
    /// (endpoint, content_source, custody, relay, gateway capabilities).
    Participant,
    /// A developer backend participating as an application/service endpoint.
    ServiceBackend,
}

impl AppProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            AppProfile::Consumer => "consumer",
            AppProfile::Participant => "participant",
            AppProfile::ServiceBackend => "service_backend",
        }
    }

    pub fn parse(s: &str) -> Result<Self, AppRegistryError> {
        match s {
            "consumer" => Ok(AppProfile::Consumer),
            "participant" => Ok(AppProfile::Participant),
            "service_backend" => Ok(AppProfile::ServiceBackend),
            other => Err(AppRegistryError::UnknownProfile(other.to_owned())),
        }
    }
}

impl fmt::Display for AppProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle status of an application. Revocation is terminal and
/// authoritative everywhere.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AppStatus {
    Active,
    Revoked { at: u64, reason: String },
}

/// A registered application (the registry's record IS the truth).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppRecord {
    pub app_id: AppId,
    pub name: String,
    /// The participation profiles this app declares (scope gating input).
    pub profiles: BTreeSet<AppProfile>,
    pub created_at: u64,
    pub status: AppStatus,
    /// The app's environments (at most one per kind), keyed by environment id.
    pub environments: BTreeMap<EnvironmentId, EnvironmentRecord>,
}

impl AppRecord {
    pub fn is_active(&self) -> bool {
        matches!(self.status, AppStatus::Active)
    }
}

/// An environment of an application.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub environment_id: EnvironmentId,
    pub app_id: AppId,
    pub kind: EnvironmentKind,
    pub created_at: u64,
    pub status: EnvironmentStatus,
}

impl EnvironmentRecord {
    pub fn is_active(&self) -> bool {
        matches!(self.status, EnvironmentStatus::Active)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EnvironmentStatus {
    Active,
    Revoked { at: u64, reason: String },
}

/// Errors of the application registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRegistryError {
    /// The app id is not registered.
    UnknownApp(AppId),
    /// The app is registered but revoked — terminal truth.
    AppRevoked(AppId),
    /// The environment id is unknown for this app.
    UnknownEnvironment(EnvironmentId),
    /// The environment exists but is revoked — terminal truth.
    EnvironmentRevoked(EnvironmentId),
    /// This app already has an environment of that kind.
    DuplicateEnvironment(EnvironmentKind),
    /// The environment kind is not one of dev/staging/prod.
    UnknownEnvironmentKind(String),
    /// The profile name is unknown.
    UnknownProfile(String),
    /// App name rejected (empty or longer than 100 chars).
    InvalidName,
    /// An app must declare at least one profile.
    NoProfiles,
    /// The id mint produced a colliding id (cryptographically implausible;
    /// surfaced as an error rather than silently accepted).
    IdCollision(String),
}

impl fmt::Display for AppRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppRegistryError::UnknownApp(a) => write!(f, "unknown app: {a}"),
            AppRegistryError::AppRevoked(a) => write!(f, "app revoked: {a}"),
            AppRegistryError::UnknownEnvironment(e) => write!(f, "unknown environment: {e}"),
            AppRegistryError::EnvironmentRevoked(e) => write!(f, "environment revoked: {e}"),
            AppRegistryError::DuplicateEnvironment(k) => {
                write!(f, "app already has a {k} environment")
            }
            AppRegistryError::UnknownEnvironmentKind(k) => write!(f, "unknown environment kind: {k}"),
            AppRegistryError::UnknownProfile(p) => write!(f, "unknown profile: {p}"),
            AppRegistryError::InvalidName => f.write_str("invalid app name (1..=100 chars)"),
            AppRegistryError::NoProfiles => f.write_str("an app must declare at least one profile"),
            AppRegistryError::IdCollision(id) => write!(f, "id mint collision on {id}"),
        }
    }
}

impl std::error::Error for AppRegistryError {}

/// The application registry.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppRegistry {
    mint: IdMint,
    apps: BTreeMap<AppId, AppRecord>,
}

impl AppRegistry {
    /// A registry with the fixed well-known TEST seed (deterministic ids).
    /// Deployments use [`AppRegistry::with_seed`].
    pub fn new() -> Self {
        AppRegistry::with_seed(RegistrySeed::from_u128_pair(0x5a_e5, 0x11_a1))
    }

    /// A registry with the deployment seed.
    pub fn with_seed(seed: RegistrySeed) -> Self {
        AppRegistry { mint: IdMint::new(seed), apps: BTreeMap::new() }
    }

    /// `register_app`: mint a stable app id and record the application.
    pub fn create_app(
        &mut self,
        name: &str,
        profiles: &[AppProfile],
        at: u64,
    ) -> Result<AppRecord, AppRegistryError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(AppRegistryError::InvalidName);
        }
        if profiles.is_empty() {
            return Err(AppRegistryError::NoProfiles);
        }
        let app_id = AppId::parse(&self.mint_app_id()?)
            .expect("minted ids are well-formed by construction");
        let record = AppRecord {
            app_id: app_id.clone(),
            name: name.to_owned(),
            profiles: profiles.iter().copied().collect(),
            created_at: at,
            status: AppStatus::Active,
            environments: BTreeMap::new(),
        };
        if self.apps.insert(app_id.clone(), record.clone()).is_some() {
            return Err(AppRegistryError::IdCollision(app_id.to_string()));
        }
        Ok(record)
    }

    /// `create_environment`: add an environment of the given kind to an
    /// ACTIVE app. At most one environment per kind per app.
    pub fn create_environment(
        &mut self,
        app: &AppId,
        kind: EnvironmentKind,
        at: u64,
    ) -> Result<EnvironmentRecord, AppRegistryError> {
        let record = self.active_app(app)?;
        if record.environments.values().any(|e| e.kind == kind) {
            return Err(AppRegistryError::DuplicateEnvironment(kind));
        }
        let environment_id = EnvironmentId::parse(&self.mint_environment_id()?)
            .expect("minted ids are well-formed by construction");
        let env = EnvironmentRecord {
            environment_id: environment_id.clone(),
            app_id: app.clone(),
            kind,
            created_at: at,
            status: EnvironmentStatus::Active,
        };
        // The borrow dance: re-fetch mutable after the id mint above.
        let record = self
            .apps
            .get_mut(app)
            .ok_or(AppRegistryError::UnknownApp(app.clone()))?;
        record.environments.insert(environment_id, env.clone());
        Ok(env)
    }

    /// `revoke_app`: the authoritative, terminal, everywhere-binding
    /// revocation of an application (and, transitively, its environments).
    pub fn revoke_app(
        &mut self,
        app: &AppId,
        reason: &str,
        at: u64,
    ) -> Result<(), AppRegistryError> {
        let record = self
            .apps
            .get_mut(app)
            .ok_or(AppRegistryError::UnknownApp(app.clone()))?;
        if !record.is_active() {
            // Revoking an already-revoked app is a no-op (terminal state).
            return Ok(());
        }
        record.status = AppStatus::Revoked { at, reason: reason.to_owned() };
        for env in record.environments.values_mut() {
            env.status = EnvironmentStatus::Revoked { at, reason: reason.to_owned() };
        }
        Ok(())
    }

    /// Revoke a single environment (terminal). The app stays active.
    pub fn revoke_environment(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        reason: &str,
        at: u64,
    ) -> Result<(), AppRegistryError> {
        let record = self.active_app(app)?;
        let _ = record;
        let record = self
            .apps
            .get_mut(app)
            .ok_or(AppRegistryError::UnknownApp(app.clone()))?;
        let env_record = record
            .environments
            .get_mut(env)
            .ok_or(AppRegistryError::UnknownEnvironment(env.clone()))?;
        if !env_record.is_active() {
            return Ok(()); // terminal already
        }
        env_record.status = EnvironmentStatus::Revoked { at, reason: reason.to_owned() };
        Ok(())
    }

    /// `describe_app` — the record INCLUDING revoked ones (audit view; the
    /// status field is the truth, callers gate on it or use `active_app`).
    pub fn app(&self, app: &AppId) -> Option<&AppRecord> {
        self.apps.get(app)
    }

    /// All app records (audit/list view).
    pub fn list_apps(&self) -> Vec<&AppRecord> {
        self.apps.values().collect()
    }

    /// The app must exist AND be active — the every-subsystem fail-closed
    /// gate. Errors distinguish unknown from revoked (both deny).
    pub fn active_app(&self, app: &AppId) -> Result<&AppRecord, AppRegistryError> {
        match self.apps.get(app) {
            None => Err(AppRegistryError::UnknownApp(app.clone())),
            Some(r) if r.is_active() => Ok(r),
            Some(_) => Err(AppRegistryError::AppRevoked(app.clone())),
        }
    }

    /// An environment of an app, whatever its status.
    pub fn environment(&self, app: &AppId, env: &EnvironmentId) -> Option<&EnvironmentRecord> {
        self.apps.get(app)?.environments.get(env)
    }

    /// The environment must exist, belong to this app AND be active.
    pub fn active_environment(
        &self,
        app: &AppId,
        env: &EnvironmentId,
    ) -> Result<&EnvironmentRecord, AppRegistryError> {
        match self.environment(app, env) {
            None => Err(AppRegistryError::UnknownEnvironment(env.clone())),
            Some(e) if e.is_active() => Ok(e),
            Some(_) => Err(AppRegistryError::EnvironmentRevoked(env.clone())),
        }
    }

    /// The number of registered apps (audit/test).
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    fn mint_app_id(&mut self) -> Result<String, AppRegistryError> {
        Ok(self.mint.mint(crate::ids::IdKind::App))
    }

    fn mint_environment_id(&mut self) -> Result<String, AppRegistryError> {
        Ok(self.mint.mint(crate::ids::IdKind::Environment))
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_app() -> (AppRegistry, AppId) {
        let mut reg = AppRegistry::new();
        let app = reg
            .create_app("field-messaging", &[AppProfile::Participant, AppProfile::Consumer], 100)
            .unwrap()
            .app_id
            .clone();
        (reg, app)
    }

    #[test]
    fn create_app_validates_name_and_profiles() {
        let mut reg = AppRegistry::new();
        assert_eq!(reg.create_app("", &[AppProfile::Consumer], 1).unwrap_err(), AppRegistryError::InvalidName);
        assert_eq!(reg.create_app("   ", &[AppProfile::Consumer], 1).unwrap_err(), AppRegistryError::InvalidName);
        let long: String = std::iter::repeat('x').take(101).collect();
        assert_eq!(reg.create_app(&long, &[AppProfile::Consumer], 1).unwrap_err(), AppRegistryError::InvalidName);
        assert_eq!(reg.create_app("ok", &[], 1).unwrap_err(), AppRegistryError::NoProfiles);
        // Name is trimmed; 100 chars ok.
        assert!(reg.create_app("  ok  ", &[AppProfile::Consumer], 1).is_ok());
        assert!(reg.create_app(&"x".repeat(100), &[AppProfile::Consumer], 1).is_ok());
    }

    #[test]
    fn app_ids_are_stable_and_unique() {
        let (mut reg, a) = registry_with_app();
        let b = reg.create_app("second", &[AppProfile::ServiceBackend], 200).unwrap().app_id;
        assert_ne!(a, b);
        assert_eq!(reg.app(&a).unwrap().name, "field-messaging");
    }

    #[test]
    fn one_environment_per_kind() {
        let (mut reg, app) = registry_with_app();
        let dev = reg.create_environment(&app, EnvironmentKind::Dev, 110).unwrap();
        assert_eq!(dev.kind, EnvironmentKind::Dev);
        assert_eq!(
            reg.create_environment(&app, EnvironmentKind::Dev, 111).unwrap_err(),
            AppRegistryError::DuplicateEnvironment(EnvironmentKind::Dev)
        );
        assert!(reg.create_environment(&app, EnvironmentKind::Prod, 112).is_ok());
        assert!(reg.create_environment(&app, EnvironmentKind::Staging, 113).is_ok());
        assert_eq!(reg.app(&app).unwrap().environments.len(), 3);
    }

    #[test]
    fn revoked_environment_fails_closed_but_app_stays_active() {
        let (mut reg, app) = registry_with_app();
        let env = reg.create_environment(&app, EnvironmentKind::Prod, 110).unwrap().environment_id.clone();
        reg.revoke_environment(&app, &env, "retired", 120).unwrap();
        assert!(matches!(
            reg.active_environment(&app, &env),
            Err(AppRegistryError::EnvironmentRevoked(_))
        ));
        assert!(reg.active_app(&app).is_ok(), "app itself stays active");
        // Revoking again is a no-op (terminal).
        reg.revoke_environment(&app, &env, "again", 130).unwrap();
        // New environment of the same kind becomes possible again? NO — the
        // old environment of that kind still exists (history is retained).
        assert_eq!(
            reg.create_environment(&app, EnvironmentKind::Prod, 140).unwrap_err(),
            AppRegistryError::DuplicateEnvironment(EnvironmentKind::Prod)
        );
    }

    #[test]
    fn revoke_app_is_authoritative_and_cascades_to_environments() {
        let (mut reg, app) = registry_with_app();
        let env = reg.create_environment(&app, EnvironmentKind::Prod, 110).unwrap().environment_id.clone();
        reg.revoke_app(&app, "policy violation", 120).unwrap();
        assert!(matches!(reg.active_app(&app), Err(AppRegistryError::AppRevoked(_))));
        assert!(matches!(
            reg.active_environment(&app, &env),
            Err(AppRegistryError::EnvironmentRevoked(_))
        ));
        // describe still shows the audit record with the revoked status.
        let record = reg.app(&app).unwrap();
        assert!(matches!(
            record.status,
            AppStatus::Revoked { at: 120, ref reason } if reason == "policy violation"
        ));
        assert!(matches!(
            record.environments.get(&env).unwrap().status,
            EnvironmentStatus::Revoked { at: 120, .. }
        ));
        // No new environments on a revoked app.
        assert!(matches!(
            reg.create_environment(&app, EnvironmentKind::Dev, 130),
            Err(AppRegistryError::AppRevoked(_))
        ));
        // Double revoke: no-op, still revoked.
        reg.revoke_app(&app, "again", 140).unwrap();
        assert!(matches!(reg.active_app(&app), Err(AppRegistryError::AppRevoked(_))));
    }

    #[test]
    fn unknown_ids_fail_closed() {
        let (reg, _) = registry_with_app();
        let unknown = AppId::parse("app_aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            reg.active_app(&unknown).unwrap_err(),
            AppRegistryError::UnknownApp(unknown.clone())
        );
        assert!(reg.app(&unknown).is_none());
    }

    #[test]
    fn kind_and_profile_parse_round_trip() {
        assert_eq!(EnvironmentKind::parse("dev").unwrap(), EnvironmentKind::Dev);
        assert_eq!(EnvironmentKind::parse("staging").unwrap(), EnvironmentKind::Staging);
        assert_eq!(EnvironmentKind::parse("prod").unwrap(), EnvironmentKind::Prod);
        assert!(EnvironmentKind::parse("production").is_err());
        assert_eq!(AppProfile::parse("consumer").unwrap(), AppProfile::Consumer);
        assert_eq!(AppProfile::parse("participant").unwrap(), AppProfile::Participant);
        assert_eq!(AppProfile::parse("service_backend").unwrap(), AppProfile::ServiceBackend);
        assert!(AppProfile::parse("gateway").is_err());
    }

    #[test]
    fn environment_belongs_to_its_app_only() {
        let (mut reg, a) = registry_with_app();
        let b = reg.create_app("second", &[AppProfile::Consumer], 200).unwrap().app_id.clone();
        let env_a = reg.create_environment(&a, EnvironmentKind::Dev, 210).unwrap().environment_id.clone();
        assert!(reg.environment(&a, &env_a).is_some());
        assert!(reg.environment(&b, &env_a).is_none(), "app A's env is invisible to app B");
        assert!(matches!(
            reg.active_environment(&b, &env_a),
            Err(AppRegistryError::UnknownEnvironment(_))
        ));
    }
}
