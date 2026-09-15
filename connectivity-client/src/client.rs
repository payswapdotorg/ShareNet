//! `AdcosClient` — the ADCOS developer-API client implementing the parent
//! crate's `ConnectivityPort` trait (work item R5-002).
//!
//! This is the ONLY ShareNet component that speaks the wire: every trait
//! call is mapped onto the documented endpoint table in [`crate::wire`],
//! carried by the minimal std-TCP HTTP/1.1 exchange in [`crate::transport`].
//!
//! # Boundary laws this client enforces
//!
//! (from `spec/integrations/adcos.md` "Failure semantics" + the
//! `ConnectivityPort` trait docs)
//!
//! - **Never fabricate contract state.** A call that fails at the transport
//!   or protocol level returns an error — never a synthesized projection.
//!   Through the trait, every non-`Port` failure degrades to
//!   `PortError::ProviderUnavailable`, which by contract means "no
//!   provider answer exists".
//! - **Only VERIFIED observations reach the connectivity layer (R5-004).**
//!   `get_assurance` decodes every observation's
//!   `SignedConnectivityObservation` envelope and runs the protocol core's
//!   full admission (Ed25519 signature against the embedded provider
//!   identity, the known-contract rule, the per-(provider node_id,
//!   contract_ref) monotonic sequence gate, the freshness window) BEFORE
//!   mapping anything into `ConnectivityObservation` domain data. Unsigned,
//!   tampered, disagreeing or unknown-contract observations are typed
//!   refusals (`AdcosError::Malformed`/`AdcosError::Evidence`) — they never
//!   reach the cache, the caller, or any durable store. This IS the
//!   registry's trust boundary: "UNSIGNED observations never enter durable
//!   ShareNet state".
//! - **Cache the last accepted observation with freshness metadata.** The
//!   client keeps an internal [`ObservationCache`] (the parent's caching
//!   policy type) fed by every successful `get_assurance`; when a
//!   contract-named call later fails at transport level, the resulting
//!   `ProviderUnavailable` carries that cache's freshness bound
//!   (`last_observation_fresh_until_unix`). A server-sent 503 carries the
//!   provider's own bound through unchanged.
//! - **Observations stay read-only.** `get_assurance` returns plain data;
//!   nothing the client does with an observation can mutate ShareNet state
//!   (the cache touches nothing but its own storage).
//! - **Local validation precedes the wire.** `create_intent` validates the
//!   requirement locally (`version`, region bound) BEFORE any round trip,
//!   exactly like the parent's in-memory fake — a bad requirement never
//!   becomes a wire call.
//!
//! # Two error surfaces
//!
//! The inherent methods return the full typed [`AdcosError`]; the
//! `ConnectivityPort` implementation flattens through
//! [`Self::port_error`] into the parent's `PortError` (typed provider
//! refusals pass through; transport/protocol failures degrade to
//! `ProviderUnavailable` with the cached freshness). Tests exercise both.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sharenet_connectivity::{
    CachedObservation, ConnectivityContractProjection, ConnectivityContractRef,
    ConnectivityExecutionProjection, ConnectivityIntentRef, ConnectivityObservation,
    ConnectivityOfferRef, ConnectivityPort, ConnectivityRequirement, ObservationCache,
    PortError, DEFAULT_FRESHNESS_WINDOW_SECS,
};
use sharenet_protocol::ObservationAdmission;

use crate::error::AdcosError;
use crate::http::{HttpRequest, HttpResponse};
use crate::transport::{self, TransportConfig, TransportLimits};
use crate::wire;

/// The statuses this wire shape documents for error envelopes (see
/// [`crate::wire`]); anything else surfaces as [`AdcosError::HttpStatus`].
const ERROR_STATUSES: [u16; 6] = [400, 401, 404, 409, 422, 503];

/// Client configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdcosConfig {
    /// The ADCOS endpoint (by socket address; no DNS — documented limit).
    pub addr: SocketAddr,
    /// Connect timeout per attempt (default 2 s).
    pub connect_timeout: Duration,
    /// Read/write timeout per attempt (default 3 s).
    pub read_timeout: Duration,
    /// Maximum connection attempts per call (default 3, minimum 1).
    pub max_attempts: u32,
    /// Delay between attempts (default 50 ms).
    pub retry_delay: Duration,
    /// How long accepted observations are treated as fresh in the client's
    /// [`ObservationCache`] (default: the parent's
    /// `DEFAULT_FRESHNESS_WINDOW_SECS` = 600 s).
    pub freshness_window_secs: u64,
    /// Read caps for hostile/broken servers.
    pub limits: TransportLimits,
}

impl AdcosConfig {
    /// Defaults for `addr`: 2 s connect, 3 s read, 3 attempts, 50 ms delay,
    /// 600 s freshness window, standard limits.
    pub fn new(addr: SocketAddr) -> AdcosConfig {
        AdcosConfig {
            addr,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(3),
            max_attempts: 3,
            retry_delay: Duration::from_millis(50),
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
            limits: TransportLimits::default(),
        }
    }

    /// Builder: connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> AdcosConfig {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: read/write timeout.
    pub fn with_read_timeout(mut self, timeout: Duration) -> AdcosConfig {
        self.read_timeout = timeout;
        self
    }

    /// Builder: maximum attempts per call.
    pub fn with_max_attempts(mut self, attempts: u32) -> AdcosConfig {
        self.max_attempts = attempts;
        self
    }

    /// Builder: delay between attempts.
    pub fn with_retry_delay(mut self, delay: Duration) -> AdcosConfig {
        self.retry_delay = delay;
        self
    }

    /// Builder: observation freshness window (seconds).
    pub fn with_freshness_window_secs(mut self, secs: u64) -> AdcosConfig {
        self.freshness_window_secs = secs;
        self
    }

    /// Builder: read caps.
    pub fn with_limits(mut self, limits: TransportLimits) -> AdcosConfig {
        self.limits = limits;
        self
    }

    /// Validate: timeouts nonzero, `max_attempts >= 1`.
    pub fn validate(&self) -> Result<(), AdcosError> {
        if self.connect_timeout.is_zero() {
            return Err(AdcosError::ConfigInvalid { what: "connect_timeout" });
        }
        if self.read_timeout.is_zero() {
            return Err(AdcosError::ConfigInvalid { what: "read_timeout" });
        }
        if self.max_attempts == 0 {
            return Err(AdcosError::ConfigInvalid { what: "max_attempts" });
        }
        Ok(())
    }
}

/// The ADCOS developer-API client. Clone-free, `&self` with interior
/// mutability (one mutex around the observation cache, one around the
/// verification admission state), `Sync` — usable from multiple threads.
#[derive(Debug)]
pub struct AdcosClient {
    config: AdcosConfig,
    cache: Mutex<ObservationCache>,
    /// The R5-004 verification state: the per-(provider node_id,
    /// contract_ref) highest-seen sequence plus the known-contract set —
    /// the registry admission rule, applied to every observation before
    /// it reaches the connectivity layer.
    admission: Mutex<ObservationAdmission>,
}

impl AdcosClient {
    /// Construct a client for `config` (validated).
    pub fn new(config: AdcosConfig) -> Result<AdcosClient, AdcosError> {
        config.validate()?;
        let window = config.freshness_window_secs;
        Ok(AdcosClient {
            cache: Mutex::new(ObservationCache::new(window)),
            admission: Mutex::new(ObservationAdmission::new(window)),
            config,
        })
    }

    /// The configuration this client was built with.
    pub fn config(&self) -> &AdcosConfig {
        &self.config
    }

    /// The freshness bound of the cached (last accepted) observation for a
    /// contract — what a contract-named `ProviderUnavailable` carries.
    pub fn cached_fresh_until(&self, contract: &ConnectivityContractRef) -> Option<u64> {
        self.lock_cache().last_observation_fresh_until_unix(contract)
    }

    /// The cached (last accepted) observation for a contract, if any.
    pub fn last_accepted(&self, contract: &ConnectivityContractRef) -> Option<CachedObservation> {
        self.lock_cache().last_accepted(contract).cloned()
    }

    /// Register a contract as KNOWN to this client's verification state —
    /// the R5-004 known-contract rule (an observation for an unknown
    /// contract is never a trust grant). Contracts accepted through
    /// [`Self::accept_offer`] register automatically; callers that reload
    /// contracts from durable state after a restart (the R5-003 store's
    /// contract list) re-register through here so the rule survives the
    /// restart.
    pub fn register_known_contract(&self, contract: &ConnectivityContractRef) {
        self.lock_admission().register_contract(*contract.id());
    }

    /// The highest verified sequence seen for (provider node_id,
    /// contract_ref) by this client's admission state.
    pub fn highest_verified_sequence(
        &self,
        provider: &sharenet_protocol::NodeId,
        contract: &ConnectivityContractRef,
    ) -> Option<u64> {
        self.lock_admission()
            .highest_sequence(provider, contract.id())
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, ObservationCache> {
        self.cache
            .lock()
            .expect("adcos client observation cache lock poisoned")
    }

    fn lock_admission(&self) -> std::sync::MutexGuard<'_, ObservationAdmission> {
        self.admission
            .lock()
            .expect("adcos client admission lock poisoned")
    }

    fn transport_config(&self) -> TransportConfig {
        TransportConfig {
            addr: self.config.addr,
            connect_timeout: self.config.connect_timeout,
            read_timeout: self.config.read_timeout,
            max_attempts: self.config.max_attempts,
            retry_delay: self.config.retry_delay,
            limits: self.config.limits,
        }
    }

    /// Exchange + status check. `contract` is the call's contract context
    /// (used by the trait-level error mapping only).
    fn dispatch(
        &self,
        request: &HttpRequest,
        _contract: Option<&ConnectivityContractRef>,
    ) -> Result<HttpResponse, AdcosError> {
        let response = transport::exchange(&self.transport_config(), request)?;
        check_status(&response)?;
        Ok(response)
    }

    /// Map a typed [`AdcosError`] into the parent's `PortError` with the
    /// call's contract context: typed refusals pass through; everything else
    /// (transport, protocol, malformed) degrades to `ProviderUnavailable`
    /// carrying the cached-observation freshness bound — because when the
    /// provider cannot deliver a trustworthy answer, the caller falls back
    /// to exactly that, and no state is fabricated.
    fn port_error(
        &self,
        error: AdcosError,
        contract: Option<&ConnectivityContractRef>,
    ) -> PortError {
        match error {
            AdcosError::Port(port) => port,
            _other => PortError::ProviderUnavailable {
                last_observation_fresh_until_unix: contract
                    .and_then(|c| self.cached_fresh_until(c)),
            },
        }
    }

    // -- typed inherent surface (same names as the trait; inherent methods
    //    take precedence on a concrete `AdcosClient`) ----------------------

    /// `createIntent` — local validation first, then `POST /intents`.
    pub fn create_intent(
        &self,
        requirement: ConnectivityRequirement,
    ) -> Result<ConnectivityIntentRef, AdcosError> {
        requirement.validate().map_err(AdcosError::Port)?;
        let request = wire::intents_request(&requirement)?;
        let response = self.dispatch(&request, None)?;
        wire::parse_intent_ref_body(&response.body)
    }

    /// `discoverOffers` — `GET /intents/{id}/offers`.
    pub fn discover_offers(
        &self,
        intent: &ConnectivityIntentRef,
    ) -> Result<Vec<ConnectivityOfferRef>, AdcosError> {
        let request = wire::offers_request(intent);
        let response = self.dispatch(&request, None)?;
        wire::parse_offer_refs_body(&response.body)
    }

    /// `acceptOffer` — `POST /intents/{id}/offers/{offer}/accept`. The
    /// returned contract registers as KNOWN in the client's R5-004
    /// verification state (observations for unknown contracts are never
    /// trust grants).
    pub fn accept_offer(
        &self,
        intent: &ConnectivityIntentRef,
        offer: &ConnectivityOfferRef,
    ) -> Result<ConnectivityContractRef, AdcosError> {
        let request = wire::accept_request(intent, offer);
        let response = self.dispatch(&request, None)?;
        let contract = wire::parse_contract_ref_body(&response.body)?;
        self.register_known_contract(&contract);
        Ok(contract)
    }

    /// `getContract` — `GET /contracts/{id}`.
    pub fn get_contract(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityContractProjection, AdcosError> {
        let request = wire::contract_request(contract);
        let response = self.dispatch(&request, Some(contract))?;
        wire::parse_projection_body(&response.body)
    }

    /// `getAssurance` — `GET /contracts/{id}/assurance`. R5-004: every
    /// observation is VERIFIED (signed envelope decode, strict statement
    /// parse, DTO agreement, protocol-core admission: signature, known
    /// contract, sequence gate, freshness) before it is mapped into the
    /// connectivity domain and fed to the internal `ObservationCache` —
    /// nothing unverified is ever returned, cached or persisted. The
    /// accepting-node clock is the system clock (the adapter is the
    /// OS-facing edge; the deterministic seam is
    /// [`Self::get_assurance_at`]).
    pub fn get_assurance(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<Vec<ConnectivityObservation>, AdcosError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.get_assurance_at(contract, now)
    }

    /// `getAssurance` with an explicit accepting-node clock — the
    /// deterministic form of [`Self::get_assurance`] (tests, probes and
    /// callers that inject their own time).
    pub fn get_assurance_at(
        &self,
        contract: &ConnectivityContractRef,
        now_unix: u64,
    ) -> Result<Vec<ConnectivityObservation>, AdcosError> {
        let request = wire::assurance_request(contract);
        let response = self.dispatch(&request, Some(contract))?;
        let dtos = wire::parse_observation_dtos(&response.body)?;
        // the R5-004 trust boundary: verification happens HERE, in the
        // adapter, before anything reaches the connectivity layer
        let observations = {
            let mut admission = self.lock_admission();
            wire::verify_observation_dtos(&dtos, &mut admission, now_unix)?
        };
        let mut cache = self.lock_cache();
        for observation in &observations {
            cache.accept(observation);
        }
        Ok(observations)
    }

    /// `getExecution` — `GET /contracts/{id}/execution`.
    pub fn get_execution(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityExecutionProjection, AdcosError> {
        let request = wire::execution_request(contract);
        let response = self.dispatch(&request, Some(contract))?;
        wire::parse_execution_body(&response.body)
    }

    /// `terminate` — `POST /contracts/{id}/terminate` (idempotent at the
    /// provider).
    pub fn terminate(&self, contract: &ConnectivityContractRef) -> Result<(), AdcosError> {
        let request = wire::terminate_request(contract);
        let _response = self.dispatch(&request, Some(contract))?;
        // Success body is the empty JSON object — nothing to parse.
        Ok(())
    }
}

/// Status check: 2xx passes; the documented error statuses map through the
/// envelope; anything else is a typed `HttpStatus` outside this wire shape.
fn check_status(response: &HttpResponse) -> Result<(), AdcosError> {
    if response.is_success() {
        return Ok(());
    }
    if ERROR_STATUSES.contains(&response.status) {
        Err(wire::map_error_response(response.status, &response.body))
    } else {
        Err(AdcosError::HttpStatus { status: response.status })
    }
}

impl ConnectivityPort for AdcosClient {
    fn create_intent(
        &self,
        requirement: ConnectivityRequirement,
    ) -> Result<ConnectivityIntentRef, PortError> {
        AdcosClient::create_intent(self, requirement).map_err(|e| self.port_error(e, None))
    }

    fn discover_offers(
        &self,
        intent: &ConnectivityIntentRef,
    ) -> Result<Vec<ConnectivityOfferRef>, PortError> {
        AdcosClient::discover_offers(self, intent).map_err(|e| self.port_error(e, None))
    }

    fn accept_offer(
        &self,
        intent: &ConnectivityIntentRef,
        offer: &ConnectivityOfferRef,
    ) -> Result<ConnectivityContractRef, PortError> {
        AdcosClient::accept_offer(self, intent, offer).map_err(|e| self.port_error(e, None))
    }

    fn get_contract(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityContractProjection, PortError> {
        AdcosClient::get_contract(self, contract).map_err(|e| self.port_error(e, Some(contract)))
    }

    fn get_assurance(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<Vec<ConnectivityObservation>, PortError> {
        AdcosClient::get_assurance(self, contract).map_err(|e| self.port_error(e, Some(contract)))
    }

    fn get_execution(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityExecutionProjection, PortError> {
        AdcosClient::get_execution(self, contract).map_err(|e| self.port_error(e, Some(contract)))
    }

    fn terminate(&self, contract: &ConnectivityContractRef) -> Result<(), PortError> {
        AdcosClient::terminate(self, contract).map_err(|e| self.port_error(e, Some(contract)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_connectivity::{AcceptOutcome, ObservationKind};

    fn addr() -> SocketAddr {
        "127.0.0.1:65001".parse().expect("static addr")
    }

    #[test]
    fn config_defaults_and_builders() {
        let config = AdcosConfig::new(addr());
        assert_eq!(config.connect_timeout, Duration::from_secs(2));
        assert_eq!(config.read_timeout, Duration::from_secs(3));
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.retry_delay, Duration::from_millis(50));
        assert_eq!(
            config.freshness_window_secs,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            "the client default mirrors the parent crate's default window"
        );
        assert_eq!(config.limits, TransportLimits::default());
        let tuned = AdcosConfig::new(addr())
            .with_connect_timeout(Duration::from_millis(300))
            .with_read_timeout(Duration::from_millis(250))
            .with_max_attempts(1)
            .with_retry_delay(Duration::from_millis(5))
            .with_freshness_window_secs(120)
            .with_limits(TransportLimits {
                max_head_bytes: 1024,
                max_body_bytes: 2048,
            });
        assert_eq!(tuned.connect_timeout, Duration::from_millis(300));
        assert_eq!(tuned.read_timeout, Duration::from_millis(250));
        assert_eq!(tuned.max_attempts, 1);
        assert_eq!(tuned.retry_delay, Duration::from_millis(5));
        assert_eq!(tuned.freshness_window_secs, 120);
        assert_eq!(tuned.limits.max_head_bytes, 1024);
    }

    #[test]
    fn invalid_config_is_refused_without_panic() {
        fn refused(config: AdcosConfig) -> AdcosError {
            AdcosClient::new(config).err().expect("config refused")
        }
        assert_eq!(
            refused(AdcosConfig::new(addr()).with_max_attempts(0)),
            AdcosError::ConfigInvalid { what: "max_attempts" }
        );
        assert_eq!(
            refused(AdcosConfig::new(addr()).with_connect_timeout(Duration::ZERO)),
            AdcosError::ConfigInvalid { what: "connect_timeout" }
        );
        assert_eq!(
            refused(AdcosConfig::new(addr()).with_read_timeout(Duration::ZERO)),
            AdcosError::ConfigInvalid { what: "read_timeout" }
        );
        assert!(AdcosClient::new(AdcosConfig::new(addr())).is_ok());
    }

    #[test]
    fn internal_cache_reuses_the_parent_policy_type() {
        // The freshness behavior the client relies on: strictly-greater
        // sequences accepted, freshness = observed_at + window, replays
        // ignored — the parent's ObservationCache, embedded.
        let client = AdcosClient::new(AdcosConfig::new(addr()).with_freshness_window_secs(60))
            .expect("valid config");
        assert_eq!(
            client.config().freshness_window_secs,
            client.lock_cache().freshness_window_secs()
        );
        let contract = ConnectivityContractRef::from_id([0x11; 32]);
        let older =
            ConnectivityObservation::new(ObservationKind::ContractActivated, 1_000, contract, 1);
        let newer = ConnectivityObservation::new(ObservationKind::Degraded, 1_010, contract, 2);
        let mut cache = client.lock_cache();
        assert_eq!(cache.accept(&older), AcceptOutcome::Accepted);
        assert_eq!(cache.accept(&older), AcceptOutcome::IgnoredReplay { sequence: 1 });
        assert_eq!(cache.accept(&newer), AcceptOutcome::Accepted);
        assert_eq!(
            cache.last_observation_fresh_until_unix(&contract),
            Some(1_070),
            "observed_at 1_010 + window 60"
        );
        drop(cache);
        assert_eq!(client.cached_fresh_until(&contract), Some(1_070));
        assert_eq!(
            client.last_accepted(&contract).unwrap().observation().sequence(),
            2
        );
        // No cached observation for a contract never queried.
        let other = ConnectivityContractRef::from_id([0x22; 32]);
        assert_eq!(client.cached_fresh_until(&other), None);
    }
}
