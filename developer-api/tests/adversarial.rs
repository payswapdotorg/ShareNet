//! C2-005 adversarial verification — the contract's six mandated adversarial
//! cases as REAL tests against the composed model. Every case uses registry
//! truth only; no test asserts on implementation internals it does not
//! exercise through the public API.
//!
//! 1. forged signatures rejected (tampered payload / wrong key / bad scheme)
//! 2. replayed signed events rejected (nonce + timestamp window)
//! 3. scope escalation attempts denied
//! 4. revoked credentials rejected EVERYWHERE (registry truth, fail closed)
//! 5. app isolation (A can never read/act on B)
//! 6. rotation: old key dead, new key live, the overlap window exact

mod common;

use common::{authenticate, harness, payload, Harness, DEV_KEY_SEED, OTHER_KEY_SEED};
use ed25519_dalek::{Signer, SigningKey};
use sharenet_developer_api::*;

// ---------------------------------------------------------------------------
// Adversarial case 1 — forged signature rejected
// ---------------------------------------------------------------------------

/// Tampered payload: the event is re-delivered with one payload byte
/// changed after signing — the HMAC no longer matches (malleability kill).
#[test]
fn adversarial_forged_signature_tampered_payload_rejected() {
    let Harness { mut api, app, env, webhook, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_000)
        .expect("emit")
        .pop()
        .expect("one webhook subscribed");
    // The event belongs to OUR registration (the harness's only webhook).
    assert_eq!(emitted.signed_event.webhook_id, webhook.webhook_id);
    let mut forged = emitted.signed_event.clone();
    // Tamper: flip one character inside the signed payload.
    forged.payload = CanonicalValue::object([
        ("session".to_owned(), CanonicalValue::str("sess_7f3a")),
        ("state".to_owned(), CanonicalValue::str("CONNECTED")), // was "connected"
        ("gateway".to_owned(), CanonicalValue::str("gw_2c")),
        ("attempt".to_owned(), CanonicalValue::int(1)),
    ]);
    // The tamperer cannot re-sign: they do not hold the registered secret.
    assert_eq!(api.verify_event(&app, &forged, 2_010), Err(WebhookError::InvalidSignature));
    // The untampered event still verifies (the tamper did not poison it).
    assert!(api.verify_event(&app, &emitted.signed_event, 2_010).is_ok());
}

/// Wrong key: an attacker re-signs the SAME event bytes with their own
/// secret. The registry verifies against the REGISTERED secret only.
#[test]
fn adversarial_forged_signature_wrong_key_rejected() {
    let Harness { mut api, app, env, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_000)
        .expect("emit")
        .pop()
        .expect("one webhook");
    let mut forged = emitted.signed_event.clone();
    let attacker_secret = WebhookSecret::new(vec![0xaa; 32]).expect("len");
    forged.signature = sign_event_bytes(&attacker_secret, &forged.canonical_bytes());
    assert_eq!(api.verify_event(&app, &forged, 2_010), Err(WebhookError::InvalidSignature));
    // A raw garbage signature is rejected the same way.
    let mut garbage = emitted.signed_event.clone();
    garbage.signature = [0u8; 32];
    assert_eq!(api.verify_event(&app, &garbage, 2_011), Err(WebhookError::InvalidSignature));
    // And a VALID signature under the wrong secret on a DIFFERENT nonce
    // (a "re-signed fresh event" forgery attempt) is still rejected.
    let mut re_signed = emitted.signed_event.clone();
    re_signed.nonce = [9u8; 16];
    re_signed.signature = sign_event_bytes(&attacker_secret, &re_signed.canonical_bytes());
    assert_eq!(api.verify_event(&app, &re_signed, 2_012), Err(WebhookError::InvalidSignature));
}

/// Bad scheme: the scheme string is not exactly
/// `sharenet-webhook-hmacsha256-v1` — algorithm downgrade/confusion is a
/// typed reject, never a silent fallback.
#[test]
fn adversarial_forged_signature_bad_scheme_rejected() {
    let Harness { mut api, app, env, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_000)
        .expect("emit")
        .pop()
        .expect("one webhook");
    for bad_scheme in [
        "sharenet-webhook-hmacsha256-v2",
        "sharenet-webhook-hmacsha1-v1",
        "sha256=hex",
        "",
        "SHARENET-WEBHOOK-HMACSHA256-V1",
    ] {
        let mut forged = emitted.signed_event.clone();
        forged.scheme = bad_scheme.to_owned();
        assert_eq!(
            api.verify_event(&app, &forged, 2_010),
            Err(WebhookError::SchemeMismatch(bad_scheme.to_owned())),
            "scheme {bad_scheme:?} must be rejected as a scheme mismatch"
        );
    }
    // A tampered scheme with a RE-COMPUTED signature under the true secret
    // is still rejected: scheme confusion is checked before the HMAC.
    let mut re_signed = emitted.signed_event.clone();
    re_signed.scheme = "sharenet-webhook-hmacsha256-v2".to_owned();
    let true_secret =
        WebhookSecret::new(common::WEBHOOK_SECRET.as_bytes().to_vec()).expect("len");
    re_signed.signature = sign_event_bytes(&true_secret, &re_signed.canonical_bytes());
    assert_eq!(
        api.verify_event(&app, &re_signed, 2_011),
        Err(WebhookError::SchemeMismatch("sharenet-webhook-hmacsha256-v2".to_owned()))
    );
}

/// The developer-AUTHENTICATION forgery leg: a valid-looking challenge
/// response signed with the WRONG key is rejected, and the challenge is
/// burned either way (no brute-force surface).
#[test]
fn adversarial_forged_auth_signature_wrong_key_rejected() {
    let Harness { mut api, credential, .. } = harness();
    let challenge = api.issue_challenge(&credential, 2_000).expect("challenge");
    let attacker = SigningKey::from_bytes(&OTHER_KEY_SEED);
    let envelope =
        CredentialStore::auth_envelope(&credential, &challenge.nonce, challenge.issued_at);
    let forged = attacker.sign(&envelope).to_bytes();
    assert_eq!(
        api.verify_authentication(&credential, &challenge.nonce, &forged, 2_010),
        Err(AuthError::InvalidSignature)
    );
    // Single-use: even the CORRECT key cannot retry this challenge now.
    let real = SigningKey::from_bytes(&DEV_KEY_SEED);
    let good = real.sign(&envelope).to_bytes();
    assert_eq!(
        api.verify_authentication(&credential, &challenge.nonce, &good, 2_011),
        Err(AuthError::ChallengeUsed)
    );
    // A signature over attacker-chosen envelope bytes (not the registry's
    // challenge) never even matches a challenge: unknown.
    let junk_nonce = [7u8; 16];
    let junk = real.sign(&CredentialStore::auth_envelope(&credential, &junk_nonce, 2_000)).to_bytes();
    assert_eq!(
        api.verify_authentication(&credential, &junk_nonce, &junk, 2_012),
        Err(AuthError::UnknownChallenge)
    );
}

// ---------------------------------------------------------------------------
// Adversarial case 2 — replayed signed event rejected
// ---------------------------------------------------------------------------

/// A verified event cannot be verified again: the (webhook, event) pair is
/// in the replay guard, and the timestamp window bounds old events.
#[test]
fn adversarial_replayed_signed_event_rejected() {
    let Harness { mut api, app, env, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_000)
        .expect("emit")
        .pop()
        .expect("one webhook");
    let signed = emitted.signed_event.clone();
    assert!(api.verify_event(&app, &signed, 2_050).is_ok());
    // Replay 1: immediate re-presentation.
    assert_eq!(api.verify_event(&app, &signed, 2_051), Err(WebhookError::EventReplayed));
    // Replay 2: re-presentation at a LATER time still inside the timestamp
    // window — the guard, not the clock, catches it.
    assert_eq!(api.verify_event(&app, &signed, 2_299), Err(WebhookError::EventReplayed));
    // Replay 3: far in the future — outside the window, rejected by the
    // window check (both defenses hold independently).
    assert!(matches!(
        api.verify_event(&app, &signed, 9_999),
        Err(WebhookError::TimestampOutOfWindow { .. })
    ));
    // A stale event never verified before is rejected by the window alone.
    let stale = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 1_000)
        .expect("emit")
        .pop()
        .expect("one webhook");
    assert!(matches!(
        api.verify_event(&app, &stale.signed_event, 9_999),
        Err(WebhookError::TimestampOutOfWindow { .. })
    ));
}

/// Replay protection SURVIVES the snapshot round-trip: a verified event
/// cannot be replayed against a restored model.
#[test]
fn adversarial_replay_guard_survives_snapshot_restore() {
    let Harness { mut api, app, env, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_000)
        .expect("emit")
        .pop()
        .expect("one webhook");
    let signed = emitted.signed_event.clone();
    assert!(api.verify_event(&app, &signed, 2_050).is_ok());
    // Snapshot + restore (the persistence round-trip).
    let json = api.to_json().expect("snapshot");
    let mut restored = DeveloperApi::from_json(&json).expect("restore");
    assert_eq!(
        restored.verify_event(&app, &signed, 2_060),
        Err(WebhookError::EventReplayed),
        "replay across a restore is still a replay"
    );
    // A FRESH event on the restored model verifies normally.
    let fresh = restored
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_061)
        .expect("emit")
        .pop()
        .expect("one webhook");
    assert!(restored.verify_event(&app, &fresh.signed_event, 2_070).is_ok());
}

// ---------------------------------------------------------------------------
// Adversarial case 3 — scope escalation denied
// ---------------------------------------------------------------------------

/// The credential asks beyond its own subset, beyond the app assignment,
/// and the app asks beyond its profiles — every rung of the ladder denies
/// with a typed reason; nothing is silently upgraded.
#[test]
fn adversarial_scope_escalation_denied() {
    let Harness { mut api, app, env, credential, .. } = harness();
    // The credential holds [sessions:read, events:read].
    // Escalation 1: request a scope in the assignment but NOT in the
    // credential's subset (the least-privilege deny).
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsConnectivity, &credential, 3_000),
        ScopeDecision::Denied {
            scope: Scope::SessionsConnectivity,
            reason: ScopeDenialReason::CredentialDoesNotHoldScope
        }
    );
    // Escalation 2: request a scope NOT even in the app assignment.
    assert_eq!(
        api.decide_scope(&app, &env, Scope::AppManage, &credential, 3_000),
        ScopeDecision::Denied { scope: Scope::AppManage, reason: ScopeDenialReason::ScopeNotAssigned }
    );
    // Escalation 3: shrink the assignment below the credential's subset —
    // the app-level truth revokes effectiveness even for held scopes.
    api.assign_scopes(&app, &env, ScopeSet::parse(&["sessions:read"]).unwrap(), 3_100)
        .expect("reassign");
    assert_eq!(
        api.decide_scope(&app, &env, Scope::EventsRead, &credential, 3_200),
        ScopeDecision::Denied { scope: Scope::EventsRead, reason: ScopeDenialReason::ScopeNotAssigned }
    );
    // Escalation 4: a consumer-profile app can never even be ASSIGNED a
    // participant-only capability scope.
    let consumer = api
        .create_app("plain-browser", &[AppProfile::Consumer], 3_300)
        .expect("app")
        .app_id
        .clone();
    let cenv = api
        .create_environment(&consumer, EnvironmentKind::Dev, 3_310)
        .expect("env")
        .environment_id
        .clone();
    assert!(matches!(
        api.assign_scopes(&consumer, &cenv, ScopeSet::parse(&["participation:gateway"]).unwrap(), 3_320),
        Err(ScopeError::NotAvailableForProfile { .. })
    ));
    // And cannot mint a credential carrying it either (the subset check
    // runs against the assignment, which cannot contain it).
    let key = SigningKey::from_bytes(&OTHER_KEY_SEED).verifying_key().to_bytes();
    assert!(api
        .assign_scopes(&consumer, &cenv, ScopeSet::parse(&["sessions:read"]).unwrap(), 3_330)
        .is_ok());
    assert!(matches!(
        api.issue_credential(
            &consumer,
            &cenv,
            "esc",
            &key,
            ScopeSet::parse(&["participation:gateway", "sessions:read"]).unwrap(),
            None,
            3_340
        ),
        Err(CredentialError::ScopeSubsetViolation(_))
    ));
    // The granted scope still decides Allowed (the ladder is exact).
    assert!(matches!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 3_500),
        ScopeDecision::Allowed { .. }
    ));
}

// ---------------------------------------------------------------------------
// Adversarial case 4 — revoked credential rejected EVERYWHERE
// ---------------------------------------------------------------------------

/// After revocation, EVERY verification path fails closed from registry
/// truth — with a perfectly valid signature in hand. No caller-claimed
/// status exists in any API shape.
#[test]
fn adversarial_revoked_credential_rejected_everywhere() {
    let Harness { mut api, app, env, credential, signing, .. } = harness();
    // Pre-issue a challenge and produce a VALID signature BEFORE revocation.
    let challenge = api.issue_challenge(&credential, 4_000).expect("challenge");
    let envelope =
        CredentialStore::auth_envelope(&credential, &challenge.nonce, challenge.issued_at);
    let valid_signature = signing.sign(&envelope).to_bytes();
    // Sanity: it would have verified.
    // (A separate handshake proves the happy path in the integration suite.)
    // NOW revoke — registry truth, terminal.
    api.revoke_credential(&credential, "key material leaked", 4_005).expect("revoke");
    // Path 1: authentication with the VALID signature fails closed.
    assert!(matches!(
        api.verify_authentication(&credential, &challenge.nonce, &valid_signature, 4_010),
        Err(AuthError::CredentialRevoked(_))
    ));
    // Path 2: no new challenges are issued for it.
    assert!(matches!(
        api.issue_challenge(&credential, 4_011),
        Err(AuthError::CredentialRevoked(_))
    ));
    // Path 3: every scope decision fails closed (even previously granted).
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 4_012),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::CredentialRevoked }
    );
    // Path 4: revocation survives the snapshot round-trip (persisted truth).
    let json = api.to_json().expect("snapshot");
    let mut restored = DeveloperApi::from_json(&json).expect("restore");
    assert!(matches!(
        authenticate(&mut restored, &credential, &signing, 4_020),
        Err(AuthError::CredentialRevoked(_))
    ));
    // Path 5: the revoked credential is visibly revoked in the audit record
    // (status is REGISTRY state, not a caller flag).
    assert!(matches!(
        restored.credentials().credential(&credential).map(|c| &c.status),
        Some(CredentialStatus::Revoked { .. })
    ));
}

/// Revoking the APPLICATION revokes every credential of that app on every
/// path (registry truth cascades; the cascade is tested, not assumed).
#[test]
fn adversarial_revoked_app_rejects_all_paths_and_credentials() {
    let Harness { mut api, app, env, credential, signing, .. } = harness();
    // A second credential + a second environment, to prove the cascade
    // reaches EVERYTHING the app owns.
    let dev_env = api
        .create_environment(&app, EnvironmentKind::Dev, 4_100)
        .expect("env")
        .environment_id
        .clone();
    let key2 = SigningKey::from_bytes(&OTHER_KEY_SEED);
    api.assign_scopes(&app, &dev_env, ScopeSet::parse(&["sessions:read"]).unwrap(), 4_110)
        .expect("assign");
    let cred2 = api
        .issue_credential(
            &app,
            &dev_env,
            "dev-key",
            &key2.verifying_key().to_bytes(),
            ScopeSet::parse(&["sessions:read"]).unwrap(),
            None,
            4_120,
        )
        .expect("issue")
        .credential_id
        .clone();
    // Revoke the APP.
    api.revoke_app(&app, "policy violation", 4_200).expect("revoke app");
    // Credential 1 paths: all closed.
    assert!(matches!(
        authenticate(&mut api, &credential, &signing, 4_210),
        Err(AuthError::AppRevoked(_))
    ));
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 4_211),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::AppRevoked }
    );
    // Credential 2 paths (a different environment!): all closed too.
    assert!(matches!(
        authenticate(&mut api, &cred2, &key2, 4_212),
        Err(AuthError::AppRevoked(_))
    ));
    assert_eq!(
        api.decide_scope(&app, &dev_env, Scope::SessionsRead, &cred2, 4_213),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::AppRevoked }
    );
    // Emission is closed (no signed events leave a revoked app).
    assert!(matches!(
        api.emit_event(&app, &env, EventType::ConnectionChanged, payload(), 4_214),
        Err(WebhookError::Registry(AppRegistryError::AppRevoked(_)))
    ));
    // Issuance of new credentials is closed.
    assert!(matches!(
        api.issue_credential(
            &app,
            &env,
            "late",
            &key2.verifying_key().to_bytes(),
            ScopeSet::empty(),
            None,
            4_215
        ),
        Err(CredentialError::Registry(AppRegistryError::AppRevoked(_)))
    ));
    // New environments are closed.
    assert!(matches!(
        api.create_environment(&app, EnvironmentKind::Staging, 4_216),
        Err(AppRegistryError::AppRevoked(_))
    ));
}

// ---------------------------------------------------------------------------
// Adversarial case 5 — app isolation
// ---------------------------------------------------------------------------

/// App A can never read, act on, or verify against app B's registrations,
/// webhooks, deliveries or credentials — cross-app ids are UNKNOWN, and no
/// emission or list ever crosses the boundary.
#[test]
fn adversarial_app_isolation_never_leaks() {
    let Harness { mut api, app, env, credential, .. } = harness();
    // A second, fully-populated app B (attacker-controlled peer).
    let app_b = api.create_app("competitor", &[AppProfile::Participant], 5_000).expect("app").app_id.clone();
    let env_b = api.create_environment(&app_b, EnvironmentKind::Prod, 5_010).expect("env").environment_id.clone();
    api.assign_scopes(&app_b, &env_b, ScopeSet::parse(&["sessions:read", "events:read"]).unwrap(), 5_020)
        .expect("assign");
    let key_b = SigningKey::from_bytes(&OTHER_KEY_SEED);
    let cred_b = api
        .issue_credential(
            &app_b,
            &env_b,
            "b-key",
            &key_b.verifying_key().to_bytes(),
            ScopeSet::parse(&["sessions:read"]).unwrap(),
            None,
            5_030,
        )
        .expect("issue")
        .credential_id
        .clone();
    let webhook_b = api
        .register_webhook(
            &app_b,
            &env_b,
            "https://hooks.competitor.test/x",
            [EventType::ConnectionChanged].into_iter().collect(),
            WebhookSecret::new(vec![0x11; 32]).expect("len"),
            5_040,
        )
        .expect("webhook");

    // (a) App A's webhook list never contains B's registration.
    let a_webhooks = api.webhooks_for_app(&app);
    assert!(a_webhooks.iter().all(|w| w.app_id == app));
    assert!(!a_webhooks.iter().any(|w| w.webhook_id == webhook_b.webhook_id));
    let b_webhooks = api.webhooks_for_app(&app_b);
    assert_eq!(b_webhooks.len(), 1);
    assert_eq!(b_webhooks[0].webhook_id, webhook_b.webhook_id);

    // (b) App A's credential deciding scopes under B's (app, env) is UNKNOWN.
    assert_eq!(
        api.decide_scope(&app_b, &env_b, Scope::SessionsRead, &credential, 5_100),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownCredential }
    );
    // (c) App B's credential under A is likewise unknown.
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &cred_b, 5_101),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::UnknownCredential }
    );

    // (d) A's emission delivers ONLY to A's webhooks, never B's.
    let emitted = api.emit_event(&app, &env, EventType::ConnectionChanged, payload(), 5_200).expect("emit");
    assert_eq!(emitted.len(), 1, "A has one subscribed webhook");
    let signed_a = emitted[0].signed_event.clone();
    let a_deliveries_before = api.deliveries_for_app(&app).len();
    let b_deliveries_before = api.deliveries_for_app(&app_b).len();
    let _ = api.emit_event(&app, &env, EventType::ConnectionChanged, payload(), 5_201);
    assert_eq!(api.deliveries_for_app(&app_b).len(), b_deliveries_before, "B receives nothing of A's");
    assert_eq!(api.deliveries_for_app(&app).len(), a_deliveries_before + 1);

    // (e) A's SIGNED EVENT verified under B's app context: unknown webhook.
    assert!(matches!(
        api.verify_event(&app_b, &signed_a, 5_210),
        Err(WebhookError::UnknownWebhook(_))
    ));
    // (f) B's signed event under A's context: likewise unknown.
    let emitted_b = api
        .emit_event(&app_b, &env_b, EventType::ConnectionChanged, payload(), 5_211)
        .expect("emit")
        .pop()
        .expect("B has one webhook");
    assert!(matches!(
        api.verify_event(&app, &emitted_b.signed_event, 5_212),
        Err(WebhookError::UnknownWebhook(_))
    ));

    // (g) Credential lookups are app-scoped: A's list never contains B's.
    let a_creds = api.credentials().credentials_for_app(&app);
    assert!(a_creds.iter().all(|c| c.app_id == app));
    assert!(!a_creds.iter().any(|c| c.credential_id == cred_b));

    // (h) B cannot revoke A's webhook or credential through the store paths:
    // revocation takes the ID ONLY, so B would need the id — and even a
    // leaked id cannot VERIFY anything cross-app (proved above). The revoke
    // APIs are operator-surface in the hosted service (C3-005 authenticates
    // the caller); the MODEL's isolation guarantee is that no READ, DECISION
    // or VERIFICATION path crosses apps — (a)-(g).
}

// ---------------------------------------------------------------------------
// Adversarial case 6 — rotation
// ---------------------------------------------------------------------------

/// Zero-grace rotation: the old key is dead at the rotation instant, the new
/// key is live — there is NO window where both silently pass, and the
/// boundary is tested exactly.
#[test]
fn adversarial_rotation_zero_grace_old_dead_new_live() {
    let Harness { mut api, app, env, credential, signing, .. } = harness();
    let new_key = SigningKey::from_bytes(&OTHER_KEY_SEED);
    let successor = api
        .rotate_credential(&credential, &new_key.verifying_key().to_bytes(), 0, 6_000)
        .expect("rotate");
    // At the rotation instant and after: OLD fails everywhere.
    assert!(matches!(
        authenticate(&mut api, &credential, &signing, 6_000),
        Err(AuthError::RotationWindowEnded(_))
    ));
    assert!(matches!(
        authenticate(&mut api, &credential, &signing, 6_500),
        Err(AuthError::RotationWindowEnded(_))
    ));
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 6_001),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::RotationWindowEnded }
    );
    // NEW is live immediately.
    assert!(authenticate(&mut api, &successor.credential_id, &new_key, 6_000).is_ok());
    assert!(matches!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &successor.credential_id, 6_002),
        ScopeDecision::Allowed { .. }
    ));
    // The successor inherited the scope subset (rotation moves key material,
    // not authority shape).
    assert_eq!(successor.scopes, ScopeSet::parse(&["sessions:read", "events:read"]).unwrap());
}

/// Bounded grace: the overlap window is EXACTLY [rotate_at, rotate_at+grace)
/// — both keys authenticate inside it, ONLY the new one after it, and an
/// explicit revoke kills the old one mid-window.
#[test]
fn adversarial_rotation_overlap_window_is_exact() {
    let Harness { mut api, app, env, credential, signing, .. } = harness();
    let new_key = SigningKey::from_bytes(&OTHER_KEY_SEED);
    let successor = api
        .rotate_credential(&credential, &new_key.verifying_key().to_bytes(), 60, 7_000)
        .expect("rotate");
    // Inside the window: BOTH authenticate (the documented, explicit overlap).
    assert!(authenticate(&mut api, &credential, &signing, 7_010).is_ok());
    assert!(authenticate(&mut api, &successor.credential_id, &new_key, 7_011).is_ok());
    assert!(matches!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 7_012),
        ScopeDecision::Allowed { .. }
    ));
    // The boundary: at exactly rotate_at + grace the old credential dies.
    assert!(matches!(
        authenticate(&mut api, &credential, &signing, 7_060),
        Err(AuthError::RotationWindowEnded(_))
    ));
    assert_eq!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 7_060),
        ScopeDecision::Denied { scope: Scope::SessionsRead, reason: ScopeDenialReason::RotationWindowEnded }
    );
    // The new key is unaffected at and past the boundary.
    assert!(authenticate(&mut api, &successor.credential_id, &new_key, 7_060).is_ok());
    assert!(authenticate(&mut api, &successor.credential_id, &new_key, 7_500).is_ok());
    // Re-rotating the ROTATING credential is refused (rotate the successor).
    assert!(matches!(
        api.rotate_credential(&credential, &[1u8; 32], 0, 7_600),
        Err(CredentialError::AlreadyRotating(_))
    ));
    // Explicit revoke beats grace mid-window: a fresh rotation, revoked inside.
    let third = SigningKey::from_bytes(&[0x55; 32]);
    let successor2 = api
        .rotate_credential(&successor.credential_id, &third.verifying_key().to_bytes(), 600, 7_700)
        .expect("rotate 2");
    assert!(authenticate(&mut api, &successor.credential_id, &new_key, 7_800).is_ok());
    api.revoke_credential(&successor.credential_id, "compromised mid-window", 7_810)
        .expect("revoke");
    assert!(matches!(
        authenticate(&mut api, &successor.credential_id, &new_key, 7_820),
        Err(AuthError::CredentialRevoked(_))
    ));
    // The newest key still works.
    assert!(authenticate(&mut api, &successor2.credential_id, &third, 7_830).is_ok());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
