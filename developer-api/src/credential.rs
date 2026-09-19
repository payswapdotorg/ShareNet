//! Developer authentication and the public-key credential model (C2-005).
//!
//! # The key model (public keys only — never private material)
//!
//! The developer generates an Ed25519 keypair CLIENT-SIDE. Only the 32-byte
//! public verifying key is ever registered with the hosted API. The registry
//! never sees, stores, derives or escrows private keys (architecture lock
//! L030: node identity and private keys stay with the runtime/developer; the
//! hosted API is a control surface). Public keys are validated at
//! registration: they must decompress to a usable verifying key AND be
//! canonically encoded (RFC 8032, mirroring the repository's
//! `reference/…/identity.rs` discipline so one key has exactly one encoding).
//!
//! # Authentication (challenge/response over a canonical envelope)
//!
//! `issue_challenge` mints a single-use nonce for an ACTIVE credential.
//! `verify_authentication` checks, IN ORDER, registry truth first and
//! cryptography last:
//!
//! 1. the challenge exists, is unexpired and UNUSED (single-use: the very
//!    first verification attempt burns it, even if the signature is wrong —
//!    no brute-force surface);
//! 2. the credential exists (unknown ⇒ `UnknownCredential`);
//! 3. the credential's lifecycle status from REGISTRY TRUTH — revoked ⇒
//!    `CredentialRevoked`, rotated-away past its overlap window ⇒
//!    `RotationWindowEnded`, hard expiry passed ⇒ `CredentialExpired`;
//! 4. the app and environment are active (`AppRevoked` /
//!    `EnvironmentRevoked`) — revocation is authoritative everywhere;
//! 5. only then the Ed25519 signature over the canonical envelope:
//!
//! ```text
//! sharenet.developer-auth.v1\n<credential_id>\n<nonce_hex>\n<issued_at>\n
//! ```
//!
//! The signature is verified with the PUBLIC key registered for exactly that
//! credential — never a caller-supplied key.
//!
//! # Rotation (explicit, bounded overlap)
//!
//! `rotate` issues a successor credential and moves the old one to
//! `Rotating { dies_at: at + grace_secs }`. With `grace_secs = 0` the old key
//! is dead at the rotation instant (no overlap at all). With a positive
//! grace the overlap is EXACTLY `[at, at + grace_secs)` — a defined, testable
//! window, never a silent one. An explicit `revoke` beats rotation grace: a
//! revoked credential is dead immediately even mid-window.
//!
//! # Least privilege
//!
//! Each credential carries its own scope SUBSET (validated against the
//! app/environment assignment by the facade at issue time; enforced at
//! decision time by [`crate::scopes::decide_scope`]).

use crate::app::{AppRegistry, AppRegistryError};
use crate::ids::{hex_encode, AppId, CredentialId, EntryMap, EnvironmentId, IdMint, RegistrySeed};
use crate::scopes::ScopeSet;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The default lifetime of an authentication challenge (seconds).
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 300;

/// Canonical envelope prefix for developer authentication signatures.
pub const AUTH_ENVELOPE_PREFIX: &str = "sharenet.developer-auth.v1";

/// Lifecycle status of a credential.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CredentialStatus {
    Active,
    /// Revoked — terminal, authoritative everywhere.
    Revoked { at: u64, reason: String },
    /// Rotated away: still authenticatable ONLY inside the explicit overlap
    /// window `[rotated_at, dies_at)`; dead from `dies_at` on.
    Rotating { rotated_at: u64, dies_at: u64, successor: CredentialId },
}

/// A registered developer credential (public-key model).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub credential_id: CredentialId,
    pub app_id: AppId,
    pub environment_id: EnvironmentId,
    /// Human label (display only, never security-relevant).
    pub label: String,
    /// The registered Ed25519 public verifying key (canonical encoding).
    pub public_key: [u8; 32],
    /// This credential's own scope subset (least privilege).
    pub scopes: ScopeSet,
    pub created_at: u64,
    /// Optional hard expiry (unix seconds). `None` = no expiry configured.
    pub expires_at: Option<u64>,
    pub status: CredentialStatus,
}

impl CredentialRecord {
    /// True when this credential is currently authenticatable for lifecycle
    /// reasons alone (app/environment status checked separately).
    pub fn is_live_at(&self, at: u64) -> bool {
        match &self.status {
            CredentialStatus::Active => true,
            CredentialStatus::Rotating { dies_at, .. } => at < *dies_at,
            CredentialStatus::Revoked { .. } => false,
        }
    }
}

/// A single-use authentication challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub credential_id: CredentialId,
    pub nonce: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChallengeRecord {
    nonce: [u8; 16],
    issued_at: u64,
    expires_at: u64,
    /// `Some(burned_at)` once a verification attempt consumed the challenge.
    used: Option<u64>,
}

/// What a successful authentication proves (registry-derived identity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedIdentity {
    pub credential_id: CredentialId,
    pub app_id: AppId,
    pub environment_id: EnvironmentId,
    pub scopes: ScopeSet,
    pub authenticated_at: u64,
}

/// Errors of the credential module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    UnknownCredential(CredentialId),
    /// The credential exists but is revoked.
    CredentialRevoked(CredentialId),
    /// The credential is mid-rotation but the overlap window has ended.
    RotationWindowEnded(CredentialId),
    /// The credential's hard expiry has passed.
    CredentialExpired(CredentialId),
    /// The credential is already rotating; rotate the successor instead.
    AlreadyRotating(CredentialId),
    /// The public key bytes are not a canonical Ed25519 verifying key.
    InvalidPublicKey,
    /// The credential label is invalid (1..=100 chars).
    InvalidLabel,
    /// The scope subset failed validation (must be a subset of the
    /// app/environment assignment).
    ScopeSubsetViolation(String),
    /// Upstream registry truth denied the operation.
    Registry(AppRegistryError),
    /// The id mint produced a colliding id (surfaced, never accepted).
    IdCollision(String),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::UnknownCredential(c) => write!(f, "unknown credential: {c}"),
            CredentialError::CredentialRevoked(c) => write!(f, "credential revoked: {c}"),
            CredentialError::RotationWindowEnded(c) => {
                write!(f, "credential rotation window ended: {c}")
            }
            CredentialError::CredentialExpired(c) => write!(f, "credential expired: {c}"),
            CredentialError::AlreadyRotating(c) => {
                write!(f, "credential already rotating: {c}")
            }
            CredentialError::InvalidPublicKey => f.write_str("invalid public key"),
            CredentialError::InvalidLabel => f.write_str("invalid credential label (1..=100 chars)"),
            CredentialError::ScopeSubsetViolation(detail) => {
                write!(f, "credential scope subset violation: {detail}")
            }
            CredentialError::Registry(e) => write!(f, "registry: {e}"),
            CredentialError::IdCollision(id) => write!(f, "id mint collision on {id}"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Errors of the authentication (verification) path. Every failure mode is
/// typed; all of them fail CLOSED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    UnknownCredential(CredentialId),
    /// No challenge with this nonce was issued for this credential.
    UnknownChallenge,
    /// The challenge existed but its TTL has passed.
    ChallengeExpired,
    /// The challenge was already used (single-use, burned on first attempt).
    ChallengeUsed,
    CredentialRevoked(CredentialId),
    RotationWindowEnded(CredentialId),
    CredentialExpired(CredentialId),
    AppRevoked(AppId),
    EnvironmentRevoked(EnvironmentId),
    /// The signature does not verify under the credential's registered key.
    InvalidSignature,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UnknownCredential(c) => write!(f, "unknown credential: {c}"),
            AuthError::UnknownChallenge => f.write_str("unknown challenge"),
            AuthError::ChallengeExpired => f.write_str("challenge expired"),
            AuthError::ChallengeUsed => f.write_str("challenge already used"),
            AuthError::CredentialRevoked(c) => write!(f, "credential revoked: {c}"),
            AuthError::RotationWindowEnded(c) => {
                write!(f, "credential rotation window ended: {c}")
            }
            AuthError::CredentialExpired(c) => write!(f, "credential expired: {c}"),
            AuthError::AppRevoked(a) => write!(f, "app revoked: {a}"),
            AuthError::EnvironmentRevoked(e) => write!(f, "environment revoked: {e}"),
            AuthError::InvalidSignature => f.write_str("invalid signature"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The credential store: credentials + issued challenges. All state is
/// derived from HERE plus the app registry — no caller-claimed facts exist in
/// any verification path.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialStore {
    mint: IdMint,
    credentials: BTreeMap<CredentialId, CredentialRecord>,
    /// Single-use challenges, keyed flat by (credential, nonce).
    challenges: EntryMap<(CredentialId, [u8; 16]), ChallengeRecord>,
    challenge_ttl_secs: u64,
}

impl CredentialStore {
    /// A store with the fixed well-known TEST seed (deterministic ids).
    pub fn new() -> Self {
        CredentialStore::with_seed(RegistrySeed::from_u128_pair(0x5a_e5, 0x11_a2))
    }

    pub fn with_seed(seed: RegistrySeed) -> Self {
        CredentialStore {
            mint: IdMint::new(seed),
            credentials: BTreeMap::new(),
            challenges: EntryMap(BTreeMap::new()),
            challenge_ttl_secs: DEFAULT_CHALLENGE_TTL_SECS,
        }
    }

    /// Override the challenge TTL (the hosted service may tune this).
    pub fn set_challenge_ttl_secs(&mut self, ttl: u64) {
        self.challenge_ttl_secs = ttl.max(1);
    }

    pub fn challenge_ttl_secs(&self) -> u64 {
        self.challenge_ttl_secs
    }

    /// `issue_client_credentials`: register a PUBLIC key as a new credential
    /// for an active (app, environment), with its own scope subset.
    pub fn issue(
        &mut self,
        apps: &AppRegistry,
        app: &AppId,
        env: &EnvironmentId,
        label: &str,
        public_key: &[u8; 32],
        scopes: ScopeSet,
        expires_at: Option<u64>,
        at: u64,
    ) -> Result<CredentialRecord, CredentialError> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 100 {
            return Err(CredentialError::InvalidLabel);
        }
        validate_public_key(public_key)?;
        apps.active_app(app).map_err(CredentialError::Registry)?;
        apps.active_environment(app, env).map_err(CredentialError::Registry)?;
        let credential_id =
            CredentialId::parse(&self.mint.mint(crate::ids::IdKind::Credential))
                .expect("minted ids are well-formed by construction");
        let record = CredentialRecord {
            credential_id: credential_id.clone(),
            app_id: app.clone(),
            environment_id: env.clone(),
            label: label.to_owned(),
            public_key: *public_key,
            scopes,
            created_at: at,
            expires_at,
            status: CredentialStatus::Active,
        };
        if self.credentials.insert(credential_id.clone(), record.clone()).is_some() {
            return Err(CredentialError::IdCollision(credential_id.to_string()));
        }
        Ok(record)
    }

    /// `rotate_credentials`: issue a successor credential under a NEW public
    /// key and move the old one into an explicit, bounded overlap window
    /// (`grace_secs == 0` ⇒ no overlap at all). The successor inherits the
    /// label, scopes and expiry of the rotated credential.
    pub fn rotate(
        &mut self,
        apps: &AppRegistry,
        credential: &CredentialId,
        new_public_key: &[u8; 32],
        grace_secs: u64,
        at: u64,
    ) -> Result<CredentialRecord, CredentialError> {
        validate_public_key(new_public_key)?;
        let old = self
            .credentials
            .get(credential)
            .ok_or_else(|| CredentialError::UnknownCredential(credential.clone()))?;
        match &old.status {
            CredentialStatus::Revoked { .. } => {
                return Err(CredentialError::CredentialRevoked(credential.clone()))
            }
            CredentialStatus::Rotating { .. } => {
                return Err(CredentialError::AlreadyRotating(credential.clone()))
            }
            CredentialStatus::Active => {}
        }
        apps.active_app(&old.app_id).map_err(CredentialError::Registry)?;
        apps.active_environment(&old.app_id, &old.environment_id)
            .map_err(CredentialError::Registry)?;
        let successor_id =
            CredentialId::parse(&self.mint.mint(crate::ids::IdKind::Credential))
                .expect("minted ids are well-formed by construction");
        let successor = CredentialRecord {
            credential_id: successor_id.clone(),
            app_id: old.app_id.clone(),
            environment_id: old.environment_id.clone(),
            label: old.label.clone(),
            public_key: *new_public_key,
            scopes: old.scopes.clone(),
            created_at: at,
            expires_at: old.expires_at,
            status: CredentialStatus::Active,
        };
        if self.credentials.insert(successor_id.clone(), successor.clone()).is_some() {
            return Err(CredentialError::IdCollision(successor_id.to_string()));
        }
        let old = self.credentials.get_mut(credential).expect("checked above");
        old.status = CredentialStatus::Rotating {
            rotated_at: at,
            dies_at: at.saturating_add(grace_secs),
            successor: successor_id,
        };
        Ok(successor)
    }

    /// `revoke` a credential — terminal, authoritative everywhere, beats any
    /// rotation grace. Revoking an already-revoked credential is a no-op.
    pub fn revoke(
        &mut self,
        credential: &CredentialId,
        reason: &str,
        at: u64,
    ) -> Result<(), CredentialError> {
        let record = self
            .credentials
            .get_mut(credential)
            .ok_or_else(|| CredentialError::UnknownCredential(credential.clone()))?;
        if matches!(record.status, CredentialStatus::Revoked { .. }) {
            return Ok(());
        }
        record.status = CredentialStatus::Revoked { at, reason: reason.to_owned() };
        Ok(())
    }

    /// A credential record, whatever its status (audit view).
    pub fn credential(&self, credential: &CredentialId) -> Option<&CredentialRecord> {
        self.credentials.get(credential)
    }

    /// All credentials of one app (the app-scoped audit list — never another
    /// app's).
    pub fn credentials_for_app(&self, app: &AppId) -> Vec<&CredentialRecord> {
        self.credentials.values().filter(|c| c.app_id == *app).collect()
    }

    /// The canonical bytes a developer signs for authentication.
    pub fn auth_envelope(
        credential: &CredentialId,
        nonce: &[u8; 16],
        issued_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(AUTH_ENVELOPE_PREFIX.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(credential.as_str().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(hex_encode(nonce).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(issued_at.to_string().as_bytes());
        out.push(b'\n');
        out
    }

    /// `issue_challenge` — mint a single-use challenge nonce for a currently
    /// authenticatable credential (fail closed at issue time).
    pub fn issue_challenge(
        &mut self,
        apps: &AppRegistry,
        credential: &CredentialId,
        now: u64,
    ) -> Result<AuthChallenge, AuthError> {
        let record = self
            .credentials
            .get(credential)
            .ok_or_else(|| AuthError::UnknownCredential(credential.clone()))?;
        self.assert_credential_live(record, now)?;
        apps.active_app(&record.app_id).map_err(|_| AuthError::AppRevoked(record.app_id.clone()))?;
        apps.active_environment(&record.app_id, &record.environment_id)
            .map_err(|_| AuthError::EnvironmentRevoked(record.environment_id.clone()))?;
        let nonce = self.mint.mint_nonce(crate::ids::NonceNamespace::AuthChallenge);
        let challenge = AuthChallenge {
            credential_id: credential.clone(),
            nonce,
            issued_at: now,
            expires_at: now.saturating_add(self.challenge_ttl_secs),
        };
        let record = ChallengeRecord {
            nonce,
            issued_at: now,
            expires_at: challenge.expires_at,
            used: None,
        };
        self.challenges.insert((credential.clone(), nonce), record);
        Ok(challenge)
    }

    /// `verify_authentication` — the total, fail-closed verification path.
    /// Registry truth first (challenge single-use, credential lifecycle, app
    /// and environment status), cryptography last. The FIRST attempt burns
    /// the challenge, whatever its outcome (no brute-force surface).
    pub fn verify_authentication(
        &mut self,
        apps: &AppRegistry,
        credential: &CredentialId,
        nonce: &[u8; 16],
        signature: &[u8; 64],
        now: u64,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        // 1. The challenge must exist for THIS credential, be unexpired and
        //    unused. It is burned on this attempt.
        let challenge = self
            .challenges
            .get_mut(&(credential.clone(), *nonce))
            .ok_or(AuthError::UnknownChallenge)?;
        if now >= challenge.expires_at {
            return Err(AuthError::ChallengeExpired);
        }
        if challenge.used.is_some() {
            return Err(AuthError::ChallengeUsed);
        }
        challenge.used = Some(now);
        let issued_at = challenge.issued_at;
        // 2. The credential must exist.
        let record = self
            .credentials
            .get(credential)
            .ok_or_else(|| AuthError::UnknownCredential(credential.clone()))?;
        // 3. Lifecycle truth (revocation/expiry/rotation window).
        self.assert_credential_live(record, now)?;
        // 4. App/environment registry truth.
        apps.active_app(&record.app_id)
            .map_err(|_| AuthError::AppRevoked(record.app_id.clone()))?;
        apps.active_environment(&record.app_id, &record.environment_id)
            .map_err(|_| AuthError::EnvironmentRevoked(record.environment_id.clone()))?;
        // 5. Signature over the canonical envelope with the REGISTERED key.
        let envelope = Self::auth_envelope(credential, nonce, issued_at);
        let verifying_key = VerifyingKey::from_bytes(&record.public_key)
            .expect("registered keys are validated at issue/rotate time");
        let sig = Signature::from_slice(signature).map_err(|_| AuthError::InvalidSignature)?;
        verifying_key
            .verify(&envelope, &sig)
            .map_err(|_| AuthError::InvalidSignature)?;
        Ok(AuthenticatedIdentity {
            credential_id: credential.clone(),
            app_id: record.app_id.clone(),
            environment_id: record.environment_id.clone(),
            scopes: record.scopes.clone(),
            authenticated_at: now,
        })
    }

    fn assert_credential_live(
        &self,
        record: &CredentialRecord,
        now: u64,
    ) -> Result<(), AuthError> {
        match &record.status {
            CredentialStatus::Revoked { .. } => {
                Err(AuthError::CredentialRevoked(record.credential_id.clone()))
            }
            CredentialStatus::Rotating { dies_at, .. } if now >= *dies_at => {
                Err(AuthError::RotationWindowEnded(record.credential_id.clone()))
            }
            CredentialStatus::Rotating { .. } | CredentialStatus::Active => {
                if let Some(expires_at) = record.expires_at {
                    if now >= expires_at {
                        return Err(AuthError::CredentialExpired(record.credential_id.clone()));
                    }
                }
                Ok(())
            }
        }
    }

    /// Drop expired challenges (state hygiene; called by the facade on
    /// snapshot so persisted state stays bounded).
    pub fn prune_challenges(&mut self, now: u64) {
        self.challenges.retain(|_, c| c.expires_at > now && c.used.is_none());
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Public-key validation: must decompress to a usable Ed25519 verifying key
/// AND be canonically encoded (RFC 8032: the y-coordinate must be < p, so one
/// key has exactly one encoding — the same discipline as
/// `reference/…/identity.rs`).
fn validate_public_key(public_key: &[u8; 32]) -> Result<(), CredentialError> {
    if !is_canonical_ed25519_point_encoding(public_key) {
        return Err(CredentialError::InvalidPublicKey);
    }
    VerifyingKey::from_bytes(public_key).map_err(|_| CredentialError::InvalidPublicKey)?;
    Ok(())
}

/// RFC 8032 canonical-encoding check for a compressed Edwards point (mirrors
/// the repository's protocol-core `identity.rs` rule).
fn is_canonical_ed25519_point_encoding(b: &[u8; 32]) -> bool {
    let mut y = *b;
    y[31] &= 0x7f; // strip the sign bit
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    for i in (0..32).rev() {
        if y[i] > P[i] {
            return false;
        }
        if y[i] < P[i] {
            return true;
        }
    }
    false // y == p is also non-canonical
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppProfile, AppRegistry, EnvironmentKind};
    use crate::ids::hex_decode;
    use crate::scopes::ScopeSet;
    use ed25519_dalek::{Signer, SigningKey};

    fn setup() -> (AppRegistry, CredentialStore, AppId, EnvironmentId, CredentialId, SigningKey) {
        let mut apps = AppRegistry::new();
        let app = apps
            .create_app("messaging", &[AppProfile::Participant], 1_000)
            .unwrap()
            .app_id
            .clone();
        let env = apps
            .create_environment(&app, EnvironmentKind::Prod, 1_010)
            .unwrap()
            .environment_id
            .clone();
        let mut creds = CredentialStore::new();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let cred = creds
            .issue(
                &apps,
                &app,
                &env,
                "ci",
                &signing.verifying_key().to_bytes(),
                ScopeSet::parse(&["sessions:read"]).unwrap(),
                Some(50_000),
                1_100,
            )
            .unwrap();
        (apps, creds, app, env, cred.credential_id.clone(), signing)
    }

    fn authenticate(
        creds: &mut CredentialStore,
        apps: &AppRegistry,
        cred: &CredentialId,
        signing: &SigningKey,
        now: u64,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        let challenge = creds.issue_challenge(apps, cred, now)?;
        let envelope = CredentialStore::auth_envelope(cred, &challenge.nonce, challenge.issued_at);
        let sig = signing.sign(&envelope).to_bytes();
        creds.verify_authentication(apps, cred, &challenge.nonce, &sig, now)
    }

    #[test]
    fn happy_path_authentication() {
        let (apps, mut creds, app, env, cred, signing) = setup();
        let identity = authenticate(&mut creds, &apps, &cred, &signing, 1_200).unwrap();
        assert_eq!(identity.app_id, app);
        assert_eq!(identity.environment_id, env);
        assert_eq!(identity.credential_id, cred);
        assert_eq!(identity.scopes, ScopeSet::parse(&["sessions:read"]).unwrap());
    }

    #[test]
    fn challenge_is_single_use_even_on_success() {
        let (apps, mut creds, _, _, cred, signing) = setup();
        let challenge = creds.issue_challenge(&apps, &cred, 1_200).unwrap();
        let envelope = CredentialStore::auth_envelope(&cred, &challenge.nonce, challenge.issued_at);
        let sig = signing.sign(&envelope).to_bytes();
        assert!(creds
            .verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_210)
            .is_ok());
        // The SAME challenge cannot be reused (replay).
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_211),
            Err(AuthError::ChallengeUsed)
        );
    }

    #[test]
    fn challenge_is_burned_even_on_bad_signature() {
        let (apps, mut creds, _, _, cred, _) = setup();
        let challenge = creds.issue_challenge(&apps, &cred, 1_200).unwrap();
        let bad_sig = [0u8; 64];
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &bad_sig, 1_210),
            Err(AuthError::InvalidSignature)
        );
        // Burned: even the CORRECT signature now fails with ChallengeUsed.
        let envelope = CredentialStore::auth_envelope(&cred, &challenge.nonce, challenge.issued_at);
        let sig = SigningKey::from_bytes(&[7u8; 32]).sign(&envelope).to_bytes();
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_211),
            Err(AuthError::ChallengeUsed)
        );
    }

    #[test]
    fn wrong_key_and_tampered_envelope_fail() {
        let (apps, mut creds, _, _, cred, _) = setup();
        let challenge = creds.issue_challenge(&apps, &cred, 1_200).unwrap();
        let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
        let envelope = CredentialStore::auth_envelope(&cred, &challenge.nonce, challenge.issued_at);
        let sig = wrong_key.sign(&envelope).to_bytes();
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_210),
            Err(AuthError::InvalidSignature)
        );
        // Unknown challenge nonce.
        let fresh = creds.issue_challenge(&apps, &cred, 1_220).unwrap();
        let _ = fresh;
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &[0u8; 16], &[0u8; 64], 1_221),
            Err(AuthError::UnknownChallenge)
        );
    }

    #[test]
    fn expired_challenge_fails() {
        let (apps, mut creds, _, _, cred, signing) = setup();
        let challenge = creds.issue_challenge(&apps, &cred, 1_000).unwrap();
        let envelope = CredentialStore::auth_envelope(&cred, &challenge.nonce, challenge.issued_at);
        let sig = signing.sign(&envelope).to_bytes();
        // Default TTL 300: expired at 1_400.
        assert_eq!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_400),
            Err(AuthError::ChallengeExpired)
        );
    }

    #[test]
    fn revoked_credential_fails_closed_even_with_valid_signature() {
        let (apps, mut creds, _, _, cred, _signing) = setup();
        creds.revoke(&cred, "leaked", 1_150).unwrap();
        // Challenge issuance fails closed too.
        assert!(matches!(
            creds.issue_challenge(&apps, &cred, 1_200),
            Err(AuthError::CredentialRevoked(_))
        ));
        // But even a pre-issued challenge + valid signature fails closed.
        // (Issue before revoke, then revoke, then verify.)
        let (apps2, mut creds2, _, _, cred2, signing2) = setup();
        let challenge = creds2.issue_challenge(&apps2, &cred2, 1_200).unwrap();
        let envelope =
            CredentialStore::auth_envelope(&cred2, &challenge.nonce, challenge.issued_at);
        let sig = signing2.sign(&envelope).to_bytes();
        creds2.revoke(&cred2, "leaked", 1_205).unwrap();
        assert!(matches!(
            creds2.verify_authentication(&apps2, &cred2, &challenge.nonce, &sig, 1_210),
            Err(AuthError::CredentialRevoked(_))
        ));
        // The signature was valid (key material unchanged): revoked-first
        // ordering proves the denial came from registry truth, not crypto.
        assert_eq!(
            creds2.credential(&cred2).unwrap().status,
            CredentialStatus::Revoked { at: 1_205, reason: "leaked".to_owned() }
        );
    }

    #[test]
    fn revoked_app_and_environment_fail_closed() {
        let (mut apps, mut creds, _, env, cred, signing) = setup();
        let challenge = creds.issue_challenge(&apps, &cred, 1_200).unwrap();
        let envelope = CredentialStore::auth_envelope(&cred, &challenge.nonce, challenge.issued_at);
        let sig = signing.sign(&envelope).to_bytes();
        apps.revoke_environment(&cred_app(&creds, &cred), &env, "retired", 1_205).unwrap();
        assert!(matches!(
            creds.verify_authentication(&apps, &cred, &challenge.nonce, &sig, 1_210),
            Err(AuthError::EnvironmentRevoked(_))
        ));
        let (mut apps2, mut creds2, _, _, cred2, signing2) = setup();
        let challenge2 = creds2.issue_challenge(&apps2, &cred2, 1_200).unwrap();
        let envelope2 =
            CredentialStore::auth_envelope(&cred2, &challenge2.nonce, challenge2.issued_at);
        let sig2 = signing2.sign(&envelope2).to_bytes();
        apps2.revoke_app(&cred_app(&creds2, &cred2), "gone", 1_205).unwrap();
        assert!(matches!(
            creds2.verify_authentication(&apps2, &cred2, &challenge2.nonce, &sig2, 1_210),
            Err(AuthError::AppRevoked(_))
        ));
    }

    fn cred_app(creds: &CredentialStore, cred: &CredentialId) -> AppId {
        creds.credential(cred).unwrap().app_id.clone()
    }

    #[test]
    fn rotation_zero_grace_kills_old_key_instantly() {
        let (apps, mut creds, _, _, cred, _) = setup();
        let new_key = SigningKey::from_bytes(&[9u8; 32]);
        let successor =
            creds.rotate(&apps, &cred, &new_key.verifying_key().to_bytes(), 0, 2_000).unwrap();
        // Old credential: dead at and after the rotation instant.
        assert!(matches!(
            creds.issue_challenge(&apps, &cred, 2_000),
            Err(AuthError::RotationWindowEnded(_))
        ));
        assert!(matches!(
            creds.issue_challenge(&apps, &cred, 2_001),
            Err(AuthError::RotationWindowEnded(_))
        ));
        // New credential: live immediately.
        assert!(creds.issue_challenge(&apps, &successor.credential_id, 2_000).is_ok());
    }

    #[test]
    fn rotation_overlap_window_is_exact() {
        let (apps, mut creds, _, _, cred, old_signing) = setup();
        let new_key = SigningKey::from_bytes(&[9u8; 32]);
        let successor =
            creds.rotate(&apps, &cred, &new_key.verifying_key().to_bytes(), 60, 3_000).unwrap();
        // Inside the window [3000, 3060): the OLD credential still authenticates.
        assert!(authenticate(&mut creds, &apps, &cred, &old_signing, 3_010).is_ok());
        assert!(authenticate(&mut creds, &apps, &successor.credential_id, &new_key, 3_010).is_ok());
        // At the boundary and beyond: old dead, new alive.
        assert!(matches!(
            authenticate(&mut creds, &apps, &cred, &old_signing, 3_060),
            Err(AuthError::RotationWindowEnded(_))
        ));
        assert!(authenticate(&mut creds, &apps, &cred, &old_signing, 3_500).is_err());
        assert!(authenticate(&mut creds, &apps, &successor.credential_id, &new_key, 3_500).is_ok());
        // Rotating the rotating credential again is refused.
        assert!(matches!(
            creds.rotate(&apps, &cred, &[0u8; 32], 0, 3_600),
            Err(CredentialError::AlreadyRotating(_))
        ));
    }

    #[test]
    fn explicit_revoke_beats_rotation_grace() {
        let (apps, mut creds, _, _, cred, _) = setup();
        let new_key = SigningKey::from_bytes(&[9u8; 32]);
        creds.rotate(&apps, &cred, &new_key.verifying_key().to_bytes(), 600, 4_000).unwrap();
        // Mid-window explicit revoke: dead immediately, everywhere.
        creds.revoke(&cred, "compromised", 4_100).unwrap();
        assert!(matches!(
            creds.issue_challenge(&apps, &cred, 4_110),
            Err(AuthError::CredentialRevoked(_))
        ));
    }

    #[test]
    fn expiry_is_enforced() {
        let (apps, mut creds, _, _, cred, signing) = setup();
        // expires_at = 50_000 (set in setup).
        assert!(matches!(
            authenticate(&mut creds, &apps, &cred, &signing, 50_000),
            Err(AuthError::CredentialExpired(_))
        ));
        assert!(authenticate(&mut creds, &apps, &cred, &signing, 49_999).is_ok());
    }

    #[test]
    fn public_key_validation_rejects_non_canonical_and_undecodable() {
        let (apps, mut creds, app, env, _, _) = setup();
        // Non-canonical encoding: y >= p (all 0xff with sign bit).
        let mut bad = [0xffu8; 32];
        bad[31] = 0xff;
        assert_eq!(
            creds.issue(&apps, &app, &env, "bad", &bad, ScopeSet::empty(), None, 1).unwrap_err(),
            CredentialError::InvalidPublicKey
        );
        // y == p exactly (0xed, 0xff.., 0x7f) is non-canonical.
        let mut eq_p = [0xffu8; 32];
        eq_p[0] = 0xed;
        eq_p[31] = 0x7f;
        assert_eq!(
            creds.issue(&apps, &app, &env, "bad", &eq_p, ScopeSet::empty(), None, 1).unwrap_err(),
            CredentialError::InvalidPublicKey
        );
        // Label validation.
        assert_eq!(
            creds
                .issue(&apps, &app, &env, "   ", &[1u8; 32], ScopeSet::empty(), None, 1)
                .unwrap_err(),
            CredentialError::InvalidLabel
        );
        // A canonical, decodable key is accepted (sign bit set is fine).
        let good = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        assert!(creds.issue(&apps, &app, &env, "good", &good, ScopeSet::empty(), None, 1).is_ok());
    }

    #[test]
    fn envelope_is_deterministic_and_bound() {
        let cred = CredentialId::parse("cred_aaaaaaaaaaaaaaaa").unwrap();
        let a = CredentialStore::auth_envelope(&cred, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], 42);
        let b = CredentialStore::auth_envelope(&cred, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], 42);
        assert_eq!(a, b);
        let c = CredentialStore::auth_envelope(&cred, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17], 42);
        assert_ne!(a, c, "nonce is bound into the envelope");
        let text = String::from_utf8(a).unwrap();
        assert!(text.starts_with("sharenet.developer-auth.v1\ncred_aaaaaaaaaaaaaaaa\n"));
    }

    #[test]
    fn credentials_for_app_are_app_scoped() {
        let (mut apps, mut creds, app, env, _, _) = setup();
        let other = apps.create_app("other", &[AppProfile::Consumer], 2_000).unwrap().app_id.clone();
        let oenv = apps.create_environment(&other, EnvironmentKind::Dev, 2_010).unwrap().environment_id.clone();
        let k = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
        creds.issue(&apps, &app, &env, "a1", &k, ScopeSet::empty(), None, 2_020).unwrap();
        creds.issue(&apps, &other, &oenv, "b1", &k, ScopeSet::empty(), None, 2_021).unwrap();
        let a_creds = creds.credentials_for_app(&app);
        assert!(a_creds.iter().all(|c| c.app_id == app));
        assert_eq!(a_creds.len(), 2); // setup() issued one + this one
        let b_creds = creds.credentials_for_app(&other);
        assert_eq!(b_creds.len(), 1);
        assert!(b_creds.iter().all(|c| c.app_id == other));
    }

    #[test]
    fn hex_helpers_round_trip() {
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(hex_decode("abcd").unwrap(), vec![0xab, 0xcd]);
    }
}
