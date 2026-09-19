//! C2-005 integration verification — the end-to-end registry → credential
//! → signed webhook event → verify cycle IN-PROCESS, and the model
//! persistence round-trip. These run against the composed facade exactly as
//! the hosted service (C3-005) will drive it: registry truth, no test
//! shortcuts around the public API.

mod common;

use common::{authenticate, harness, payload, Harness, OTHER_KEY_SEED};
use ed25519_dalek::SigningKey;
use sharenet_developer_api::*;

/// The DEV-001/DEV-007 cycle in one process: register an app → environment
/// → scope assignment → public-key credential (least-privilege subset) →
/// developer authenticates by signing a challenge → typed event emitted →
/// signed webhook delivered (worker reports the outcome) → event verified
/// → quota counted → scope decisions enforce the ladder at every rung.
#[test]
fn end_to_end_registry_credential_signed_webhook_event_cycle() {
    let Harness { mut api, app, env, credential, signing, webhook } = harness();

    // --- the registry is the truth for existence -------------------------
    let described = api.describe_app(&app).expect("describe");
    assert_eq!(described.name, "field-messaging");
    assert!(described.is_active());
    assert_eq!(described.environments.len(), 1);
    assert!(described.environments.values().all(|e| e.is_active()));

    // --- developer authentication (public-key challenge/response) -------
    let identity = authenticate(&mut api, &credential, &signing, 2_000).expect("auth");
    assert_eq!(identity.app_id, app);
    assert_eq!(identity.environment_id, env);
    assert_eq!(identity.scopes, ScopeSet::parse(&["sessions:read", "events:read"]).unwrap());

    // --- scope decisions on the authenticated identity -------------------
    assert!(matches!(
        api.decide_scope(&app, &env, Scope::SessionsRead, &credential, 2_010),
        ScopeDecision::Allowed { .. }
    ));
    assert_eq!(
        api.decide_scope(&app, &env, Scope::WebhooksManage, &credential, 2_011),
        ScopeDecision::Denied { scope: Scope::WebhooksManage, reason: ScopeDenialReason::CredentialDoesNotHoldScope }
    );

    // --- typed event emission + signing ----------------------------------
    assert_eq!(webhook.url, "https://hooks.example.test/sharenet");
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_100)
        .expect("emit");
    assert_eq!(emitted.len(), 1, "exactly one subscribed webhook");
    let event = &emitted[0];
    assert_eq!(event.signed_event.event_type, EventType::ConnectionChanged);
    assert_eq!(event.signed_event.webhook_id, webhook.webhook_id);

    // --- the delivery record round-trips through the worker state machine -
    let delivery_id = event.delivery_id.clone();
    assert!(matches!(
        api.webhooks().delivery(&delivery_id).expect("record").state,
        DeliveryState::Pending
    ));
    // First attempt times out (bounded backoff), retry succeeds.
    api.record_delivery_outcome(
        &delivery_id,
        DeliveryOutcome::AttemptFailed { reason: "connect timeout".to_owned() },
        2_110,
    )
    .expect("outcome");
    let failed = api.webhooks().delivery(&delivery_id).expect("record");
    assert_eq!(failed.attempts(), 1);
    assert!(!failed.is_due(2_115), "backoff not elapsed");
    assert!(failed.is_due(2_170), "backoff elapsed (60s)");
    let delivered = api
        .record_delivery_outcome(&delivery_id, DeliveryOutcome::Delivered { http_status: 200 }, 2_170)
        .expect("outcome");
    assert!(matches!(delivered.state, DeliveryState::Delivered { http_status: 200, .. }));

    // --- the receiver verifies the SIGNED event --------------------------
    api.verify_event(&app, &event.signed_event, 2_180).expect("verify");
    // And a replay of it is rejected (the receiver's own dedup layer may
    // choose to treat the EventReplayed deny as idempotent success — the
    // model's verify_event is strictly single-verification by contract).
    assert_eq!(
        api.verify_event(&app, &event.signed_event, 2_181),
        Err(WebhookError::EventReplayed)
    );

    // --- the wire form is the documented shape ---------------------------
    let json = serde_json::to_string(&event.signed_event).expect("wire json");
    assert!(json.starts_with("{\"scheme\":\"sharenet-webhook-hmacsha256-v1\""));
    let parsed: SignedEvent = serde_json::from_str(&json).expect("wire parse");
    assert_eq!(parsed, event.signed_event);
    assert_eq!(parsed.canonical_bytes(), event.signed_event.canonical_bytes());

    // --- quota counts the app's requests ---------------------------------
    for _ in 0..59 {
        assert!(matches!(
            api.quota_consume(&app, &env, 3_000),
            QuotaDecision::Allowed { .. }
        ));
    }
    // The 60th (the free-tier default budget) still fits; the 61st limits.
    assert!(matches!(api.quota_consume(&app, &env, 3_000), QuotaDecision::Allowed { .. }));
    assert_eq!(
        api.quota_consume(&app, &env, 3_030),
        QuotaDecision::Limited { retry_after_secs: 30, reset_at: 3_060 }
    );
    // A fresh window restores the budget.
    assert!(matches!(api.quota_consume(&app, &env, 3_060), QuotaDecision::Allowed { .. }));

    // --- the app-scoped audit views show exactly this app ---------------
    let deliveries = api.deliveries_for_app(&app);
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].event_id, event.signed_event.event_id);
    let webhooks = api.webhooks_for_app(&app);
    assert_eq!(webhooks.len(), 1);
    assert_eq!(webhooks[0].webhook_id, webhook.webhook_id);
}

/// The model's persistence round-trips: snapshot → JSON → restore is
/// byte-stable and behavior-preserving (revocation and replay state
/// included; corrupt snapshots fail closed at parse time).
#[test]
fn model_persistence_round_trips() {
    let Harness { mut api, app, env, credential, signing, .. } = harness();

    // Build nontrivial state: auth, an emitted+verified event, a failed
    // delivery, quota usage, a revoked second credential.
    assert!(authenticate(&mut api, &credential, &signing, 2_000).is_ok());
    let extra_key = SigningKey::from_bytes(&OTHER_KEY_SEED);
    api.assign_scopes(&app, &env, ScopeSet::parse(&["sessions:read", "events:read", "webhooks:manage"]).unwrap(), 2_010)
        .expect("assign");
    let extra = api
        .issue_credential(
            &app,
            &env,
            "short-lived",
            &extra_key.verifying_key().to_bytes(),
            ScopeSet::parse(&["webhooks:manage"]).unwrap(),
            None,
            2_020,
        )
        .expect("issue");
    api.revoke_credential(&extra.credential_id, "test teardown", 2_030).expect("revoke");
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_100)
        .expect("emit")
        .pop()
        .expect("webhook");
    api.verify_event(&app, &emitted.signed_event, 2_110).expect("verify");
    api.record_delivery_outcome(
        &emitted.delivery_id,
        DeliveryOutcome::AttemptFailed { reason: "dns".to_owned() },
        2_120,
    )
    .expect("outcome");
    api.quota_consume(&app, &env, 3_000);

    // Round trip 1: JSON snapshot → restore.
    let json = api.to_json().expect("snapshot");
    let mut restored = DeveloperApi::from_json(&json).expect("restore");
    // Round trip 2: the restored model snapshots byte-identically.
    assert_eq!(restored.to_json().expect("snapshot 2"), json, "snapshot is byte-stable");

    // Behavior continues from restored truth:
    // (a) the revoked credential is still revoked everywhere;
    assert!(matches!(
        authenticate(&mut restored, &extra.credential_id, &extra_key, 2_200),
        Err(AuthError::CredentialRevoked(_))
    ));
    // (b) the live credential still authenticates;
    assert!(authenticate(&mut restored, &credential, &signing, 2_210).is_ok());
    // (c) the verified event is still replay-guarded;
    assert_eq!(
        restored.verify_event(&app, &emitted.signed_event, 2_220),
        Err(WebhookError::EventReplayed)
    );
    // (d) the failed delivery retains its retry schedule;
    let record = restored.webhooks().delivery(&emitted.delivery_id).expect("record");
    assert_eq!(record.attempts(), 1);
    assert!(record.is_due(2_180));
    // (e) quota counters survive;
    assert_eq!(
        restored.quota_evaluate(&app, &env, 3_001),
        QuotaDecision::Allowed { remaining: 59, reset_at: 3_060 }
    );
    // (f) a fresh event on the restored model signs, delivers and verifies.
    let fresh = restored
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 2_230)
        .expect("emit")
        .pop()
        .expect("webhook");
    assert!(restored.verify_event(&app, &fresh.signed_event, 2_240).is_ok());

    // Corrupt snapshots fail closed (no partial state).
    assert!(DeveloperApi::from_json("}not json{").is_err());
    let tampered = json.replace("field-messaging", "");
    assert!(DeveloperApi::from_json(&tampered).is_ok(), "name change is data, not corruption — restore succeeds");
    // Id-level corruption is rejected at parse time:
    let corrupt = json.replace("app_", "app_!");
    assert!(DeveloperApi::from_json(&corrupt).is_err());

    // snapshot()/restore() (the typed deep-copy form) behaves identically.
    let typed = DeveloperApi::restore(api.snapshot());
    assert!(typed.apps().active_app(&app).is_ok());
    let _ = &env;
}

/// The complete emission → verification → delivery-expiry lifecycle for an
/// unreachable endpoint (the typed expired outcome, bounded attempts).
#[test]
fn delivery_lifecycle_expires_after_bounded_attempts() {
    let Harness { mut api, app, env, .. } = harness();
    let emitted = api
        .emit_event(&app, &env, EventType::ConnectionChanged, payload(), 1_000)
        .expect("emit")
        .pop()
        .expect("webhook");
    for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
        let record = api
            .record_delivery_outcome(
                &emitted.delivery_id,
                DeliveryOutcome::AttemptFailed { reason: format!("attempt {attempt}") },
                1_000 + attempt as u64 * 100,
            )
            .expect("outcome");
        if attempt == MAX_DELIVERY_ATTEMPTS {
            assert!(matches!(record.state, DeliveryState::Expired { .. }));
        }
    }
    let final_record = api.webhooks().delivery(&emitted.delivery_id).expect("record");
    assert!(final_record.is_terminal());
    assert!(!final_record.is_due(100_000), "expired records are never re-attempted");
    // The app-scoped audit list reflects the terminal state.
    let deliveries = api.deliveries_for_app(&app);
    assert!(matches!(deliveries[0].state, DeliveryState::Expired { .. }));
}
