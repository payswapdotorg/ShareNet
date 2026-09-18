//! Shared harness for the C2-005 integration and adversarial suites.
//!
//! Builds the canonical DEV-001-shaped scenario: a participant application
//! with a prod environment, a scope assignment, an Ed25519 developer
//! keypair with a least-privilege credential, and an active webhook
//! subscribed to `connection_changed`.

use ed25519_dalek::{Signer, SigningKey};
use sharenet_developer_api::*;

/// A fixed, canonical signing seed (tests are deterministic).
pub const DEV_KEY_SEED: [u8; 32] = [0x42; 32];
/// A second, distinct signing seed (the "attacker"/rotation key).
pub const OTHER_KEY_SEED: [u8; 32] = [0x77; 32];

pub struct Harness {
    pub api: DeveloperApi,
    pub app: AppId,
    pub env: EnvironmentId,
    pub credential: CredentialId,
    pub signing: SigningKey,
    pub webhook: WebhookRegistration,
}

pub const WEBHOOK_SECRET: &str = "harness-webhook-secret";

/// The canonical application-scoped event payload.
pub fn payload() -> CanonicalValue {
    CanonicalValue::object([
        ("session".to_owned(), CanonicalValue::str("sess_7f3a")),
        ("state".to_owned(), CanonicalValue::str("connected")),
        ("gateway".to_owned(), CanonicalValue::str("gw_2c")),
        ("attempt".to_owned(), CanonicalValue::int(1)),
    ])
}

pub fn harness() -> Harness {
    let mut api = DeveloperApi::new();
    let app = api
        .create_app("field-messaging", &[AppProfile::Participant], 1_000)
        .expect("create_app")
        .app_id
        .clone();
    let env = api
        .create_environment(&app, EnvironmentKind::Prod, 1_010)
        .expect("create_environment")
        .environment_id
        .clone();
    api.assign_scopes(
        &app,
        &env,
        ScopeSet::parse(&["sessions:read", "sessions:connectivity", "events:read", "webhooks:manage"])
            .expect("scopes"),
        1_020,
    )
    .expect("assign_scopes");
    let signing = SigningKey::from_bytes(&DEV_KEY_SEED);
    let credential = api
        .issue_credential(
            &app,
            &env,
            "ci-key",
            &signing.verifying_key().to_bytes(),
            // Least privilege: the credential holds a strict subset.
            ScopeSet::parse(&["sessions:read", "events:read"]).expect("scopes"),
            Some(1_000_000),
            1_030,
        )
        .expect("issue_credential")
        .credential_id
        .clone();
    let webhook = api
        .register_webhook(
            &app,
            &env,
            "https://hooks.example.test/sharenet",
            [EventType::ConnectionChanged].into_iter().collect(),
            WebhookSecret::new(WEBHOOK_SECRET.as_bytes().to_vec()).expect("secret"),
            1_040,
        )
        .expect("register_webhook");
    Harness { api, app, env, credential, signing, webhook }
}

/// The full developer-authentication handshake over the facade.
pub fn authenticate(
    api: &mut DeveloperApi,
    credential: &CredentialId,
    signing: &SigningKey,
    now: u64,
) -> Result<AuthenticatedIdentity, AuthError> {
    let challenge = api.issue_challenge(credential, now)?;
    let envelope = CredentialStore::auth_envelope(credential, &challenge.nonce, challenge.issued_at);
    let signature = signing.sign(&envelope).to_bytes();
    api.verify_authentication(credential, &challenge.nonce, &signature, now)
}
