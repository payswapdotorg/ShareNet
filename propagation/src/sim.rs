//! The R6-005 "simulation" verify level: a bounded, seeded,
//! deterministic discrete-event contact-graph simulation of the
//! opportunistic forwarder — evidence, not a framework.
//!
//! A small world of carrying nodes and gateways runs scripted contact
//! windows (with TTLs, priorities and budgets) through the REAL
//! policy stack, both edges composed:
//!
//! - the SENDING edge (R6-005): the forwarder plans each contact over
//!   the sender's own [`DtnStoreImage`] — `forward_candidates`,
//!   manifest bytes, present slots, one-handover-per-gateway evidence;
//! - the RECEIVING edge (R6-004): the gateway takes custody of the
//!   handed-over material through [`crate::PropagationPolicy`]
//!   (`take_custody` / `receive_chunk`) — dedup, integrity, TTL and
//!   the minimum-remaining-life floor all apply exactly as on the
//!   wire;
//! - the sender notes a forward (`note_forwarded`) ONLY for handovers
//!   that landed (accepted or already-held) — a refused handover
//!   records nothing, so the custody evidence never claims a
//!   transfer that did not happen.
//!
//! Everything is deterministic (architecture §2): one
//! [`SimRng`] (SplitMix64) seeds the world's content inside the
//! scenario's SCRIPTED structure; running uses NO randomness, no
//! wall clock (every tick is the event's), no I/O, and no
//! hash-iteration (ordered maps only). The same scenario + seed
//! always produces byte-identical traces — proven by test, and by
//! running the whole binary twice.
//!
//! # The scenarios ([`SCENARIO_NAMES`])
//!
//! - `intermittent-gateway` — a partitioned node (no contacts for a
//!   long stretch) replicates its whole stock through sparse windows
//!   with three intermittent gateways; demand is fully served
//!   (every bundle reaches its replication target), progress is
//!   monotonic, and a re-contact with the same gateway serves
//!   nothing (one handover per bundle and gateway).
//! - `expiry` — bundles that expire before, at, and inside windows,
//!   plus one below the remaining-life floor: none is EVER served;
//!   the sweep evicts them; the long-lived demand is served.
//! - `tight-budget` — mixed-priority demand under count-bound and
//!   byte-bound windows: the plan order is the store's carry order
//!   (priority class, expiry urgency, id) and completion follows it
//!   strictly across rounds.
//! - `ineligible-gateway` — ineligible verdicts, windows that outlive
//!   their evidence, and plan clocks outside their windows: all
//!   typed refusals, nothing moves; the later clean contact serves.
//! - `edge-floors` — the sender's floor disabled, the receiver's at
//!   the default: a below-floor handover is refused AT THE RECEIVING
//!   EDGE (typed, R6-004) and the sender honestly notes nothing.
//!
//! # Honest scope
//!
//! The sim exercises the policy over the store IMAGE (pure,
//! in-memory) — the file-backed read/custody path across real
//! processes is the multiprocess verify level's job (the
//! `propagation_probe` binary). Gateways are sinks in this world:
//! onward Internet delivery after a gateway holds a bundle is not
//! modeled (there is no spec semantics for it yet — R8 receipts and
//! the daemon's delivery path own that).

use std::collections::BTreeMap;

use sharenet_admission::{
    AdmissionReason, AdcosEvidenceAnchor, GatewayAdmission, ShareNetEvidenceAnchor,
};
use sharenet_connectivity::{ContractState, ConnectivityContractRef};
use sharenet_dtn::{DtnStoreImage, PeerRef, CONTENT_ID_LEN};
use sharenet_protocol::ContentManifest;

use crate::contact::{ContactBudget, ContactOpportunity, GATEWAY_ID_LEN};
use crate::forwarder::{ForwarderParams, ForwardVerdict, OpportunisticForwarder};
use crate::policy::{PropagationParams, PropagationPolicy};
use crate::verdict::ManifestVerdict;
use crate::{ChunkOffer, ManifestOffer};

/// A deterministic SplitMix64 generator — the ONLY randomness in the
/// simulation, used at scenario-construction time to seed the world's
/// content inside the scripted structure. No wall clock, no
/// hash-iteration: the world and its traces are pure functions of
/// (scenario, seed).
#[derive(Debug, Clone)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    /// A generator seeded by `seed` (the zero seed is legal and
    /// deterministic like any other).
    pub fn new(seed: u64) -> Self {
        SimRng { state: seed }
    }

    /// The next raw u64 (SplitMix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// A bounded value in `0..bound` (`bound >= 1`).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound.max(1)
    }
}

/// One simulated node: a store image (all custody facts) plus the
/// chunk bytes it carries (the store image deliberately holds only
/// custody facts; the bytes are the transfer session's business —
/// here they live beside the image so handovers can move them).
#[derive(Debug, Clone)]
pub struct SimNode {
    /// The node's one-byte tag (traces and scripting).
    pub tag: u8,
    /// The node's DTN custody store (R6-003 image — all durable
    /// facts this layer decides on).
    pub image: DtnStoreImage,
    /// The carried chunk bytes, per content id, per slot (ordered
    /// maps — determinism).
    pub carried: BTreeMap<[u8; CONTENT_ID_LEN], BTreeMap<u32, Vec<u8>>>,
}

impl SimNode {
    /// An empty node.
    pub fn new(tag: u8) -> Self {
        SimNode {
            tag,
            image: DtnStoreImage::new(),
            carried: BTreeMap::new(),
        }
    }

    /// Take custody of `manifest` + `chunks` (complete) at `now`
    /// with the given carry metadata, through the store's own APIs —
    /// the seeding path a daemon drives.
    pub fn seed_bundle(
        &mut self,
        manifest: &ContentManifest,
        chunks: &[Vec<u8>],
        priority: sharenet_dtn::ServicePriority,
        now: u64,
        expires_at: u64,
        replication_target: u32,
        from_peer: &PeerRef,
    ) {
        self.image
            .admit_manifest(manifest, priority, now, expires_at, replication_target)
            .expect("sim seeding admits");
        let id = manifest.content_id();
        let slots = self.carried.entry(id).or_default();
        for (slot, chunk) in chunks.iter().enumerate() {
            self.image
                .admit_chunk(&id, slot, chunk, now)
                .expect("sim seeding verifies");
            slots.insert(slot as u32, chunk.clone());
        }
        self.image
            .record_evidence(sharenet_dtn::CustodyRecord::received(id, now, from_peer))
            .expect("sim seeding records");
    }
}

/// One scripted contact window (the encounter the scenario dictates).
#[derive(Debug, Clone)]
pub struct SimContact {
    /// The tick the window opens at.
    pub at_tick: u64,
    /// The carrying node that plans and hands over.
    pub sender_tag: u8,
    /// The gateway node that receives (its synthetic R5-005 verdict
    /// is built by the engine).
    pub gateway_tag: u8,
    /// The window width (`closes = at_tick + duration`).
    pub duration: u64,
    /// The window's byte bound.
    pub max_bytes: u64,
    /// The window's bundle-count bound.
    pub max_bundles: u32,
    /// Until when the gateway's admission evidence holds (must cover
    /// the window for an eligible contact to construct).
    pub valid_until_tick: u64,
    /// Whether the scripted verdict is `Eligible` (an ineligible
    /// gateway is a legal scripted disruption — nothing may move).
    pub eligible: bool,
    /// The clock the daemon plans at inside the window (defaults to
    /// `at_tick` when `None`; scripting a value outside the window
    /// exercises the typed clock refusals).
    pub plan_clock: Option<u64>,
}

/// One scripted world event.
#[derive(Debug, Clone)]
pub enum SimEvent {
    /// A contact window.
    Contact(SimContact),
    /// An expiry sweep: every node evicts its expired bundles at the
    /// tick (the daemon's hygiene pass).
    Evict {
        /// The sweep tick.
        at_tick: u64,
    },
}

/// A complete simulation spec: the world, the event script, and both
/// policy edges' parameters. Deterministic end to end for a fixed
/// (scenario structure, seed).
#[derive(Debug, Clone)]
pub struct SimScenario {
    /// The scenario's stable name (trace header).
    pub name: &'static str,
    /// The seed that generated the world inside the structure.
    pub seed: u64,
    /// The sending edge's parameters (R6-005).
    pub forwarder: ForwarderParams,
    /// The receiving edge's parameters (R6-004).
    pub receiving: PropagationParams,
    /// The starting world (carrying nodes AND gateways).
    pub nodes: Vec<SimNode>,
    /// The event script, executed in the given order (scripted —
    /// the builder keeps it in tick order).
    pub events: Vec<SimEvent>,
}

/// The run's counters (all derived from the trace's facts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SimStats {
    /// Contacts attempted.
    pub contacts: u64,
    /// Contacts refused at construction (typed).
    pub contacts_refused: u64,
    /// Plans produced.
    pub plans: u64,
    /// `nothing_to_forward` verdicts.
    pub nothing_to_forward: u64,
    /// Plan refusals (clocks outside windows).
    pub plan_refusals: u64,
    /// Steps planned.
    pub steps: u64,
    /// Handovers that landed (receiver accepted / already held).
    pub handovers_landed: u64,
    /// Handovers the receiving edge refused.
    pub handovers_refused: u64,
    /// Deferrals recorded (typed, per candidate).
    pub deferred: u64,
    /// Bundles evicted by sweeps.
    pub evictions: u64,
}

/// The deterministic trace: fixed-format lines, in event order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimTrace {
    lines: Vec<String>,
    stats: SimStats,
}

impl SimTrace {
    /// The trace as deterministic bytes: one line per line,
    /// newline-terminated. Identical for identical runs.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The run's counters.
    pub fn stats(&self) -> &SimStats {
        &self.stats
    }

    /// The raw trace lines (ordered).
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// A finished run: the trace plus the final world (for property
/// assertions over the nodes' durable state).
#[derive(Debug, Clone)]
pub struct SimOutcome {
    /// The deterministic trace.
    pub trace: SimTrace,
    /// The final world, by node tag.
    pub world: BTreeMap<u8, SimNode>,
}

/// The named scenarios (the binary's and the tests' vocabulary).
pub const SCENARIO_NAMES: [&str; 5] = [
    "intermittent-gateway",
    "expiry",
    "tight-budget",
    "ineligible-gateway",
    "edge-floors",
];

/// Build a named scenario with a seed (`None` for an unknown name).
pub fn scenario_by_name(name: &str, seed: u64) -> Option<SimScenario> {
    match name {
        "intermittent-gateway" => Some(scenario_intermittent_gateway(seed)),
        "expiry" => Some(scenario_expiry(seed)),
        "tight-budget" => Some(scenario_tight_budget(seed)),
        "ineligible-gateway" => Some(scenario_ineligible_gateway(seed)),
        "edge-floors" => Some(scenario_edge_floors(seed)),
        _ => None,
    }
}

/// Run a scenario to its end: every event in script order, both
/// policy edges composed, the trace accumulated deterministically.
pub fn run_scenario(scenario: SimScenario) -> SimOutcome {
    let mut nodes: BTreeMap<u8, SimNode> =
        scenario.nodes.into_iter().map(|n| (n.tag, n)).collect();
    let forwarder = OpportunisticForwarder::new(scenario.forwarder);
    let receiving = PropagationPolicy::new(scenario.receiving);
    let mut lines: Vec<String> = Vec::new();
    let mut stats = SimStats::default();
    lines.push(format!("SIM {} seed={}", scenario.name, scenario.seed));
    for node in nodes.values() {
        lines.push(format!("WORLD node={} bundles={}", node.tag, node.image.bundle_count()));
        for summary in node.image.summaries() {
            lines.push(format!(
                "HOLDS node={} content={} priority={} expires={} target={} chunks={}/{}",
                node.tag,
                short_hex(summary.content_id()),
                summary.priority(),
                summary.expires_at_unix(),
                summary.replication_target(),
                summary.present_chunk_count(),
                summary.chunk_count(),
            ));
        }
    }
    for event in scenario.events {
        match event {
            SimEvent::Evict { at_tick } => {
                for node in nodes.values_mut() {
                    for id in node.image.evict_expired(at_tick) {
                        node.carried.remove(&id);
                        lines.push(format!(
                            "EVICT t={at_tick} node={} content={}",
                            node.tag,
                            short_hex(&id)
                        ));
                        stats.evictions += 1;
                    }
                }
            }
            SimEvent::Contact(contact) => {
                stats.contacts += 1;
                run_contact(
                    &mut nodes, &forwarder, &receiving, &contact, &mut lines, &mut stats,
                );
            }
        }
    }
    lines.push(format!(
        "END contacts={} refused_contacts={} plans={} nothing={} plan_refusals={} steps={} landed={} handovers_refused={} deferred={} evictions={}",
        stats.contacts,
        stats.contacts_refused,
        stats.plans,
        stats.nothing_to_forward,
        stats.plan_refusals,
        stats.steps,
        stats.handovers_landed,
        stats.handovers_refused,
        stats.deferred,
        stats.evictions,
    ));
    SimOutcome {
        trace: SimTrace { lines, stats },
        world: nodes,
    }
}

/// Process one scripted contact: construct the typed window (or trace
/// the typed refusal), plan, and drive both edges per step.
fn run_contact(
    nodes: &mut BTreeMap<u8, SimNode>,
    forwarder: &OpportunisticForwarder,
    receiving: &PropagationPolicy,
    contact: &SimContact,
    lines: &mut Vec<String>,
    stats: &mut SimStats,
) {
    // The anti-self-spray guard (§14's spirit): a node never hands
    // over to itself — the sim refuses the scripted self-contact
    // typed (the daemon's contact builder owns this duty; the contact
    // model itself does not carry the local node's id).
    if contact.sender_tag == contact.gateway_tag {
        stats.contacts_refused += 1;
        lines.push(format!(
            "CONTACT-REFUSED t={} node={} gw={} reason=self_contact",
            contact.at_tick, contact.sender_tag, contact.gateway_tag
        ));
        return;
    }
    // The synthetic R5-005 verdict the scenario scripts (the real
    // daemon runs the admission policy over signed evidence; the sim
    // models its outcome — the contact layer only ever sees the
    // typed verdict either way).
    let verdict = if contact.eligible {
        GatewayAdmission::Eligible {
            gateway_node_id: node_id(contact.gateway_tag),
            sharenet: ShareNetEvidenceAnchor {
                link_id: [1; 32],
                observer_node_id: [2; 32],
                observed_at_unix: contact.at_tick.saturating_sub(10),
                expires_at_unix: contact.valid_until_tick,
                loss_ratio_ppm_effective: 0,
                p95_rtt_micros: 1_000,
                fresh_until_unix: contact.valid_until_tick,
            },
            adcos: AdcosEvidenceAnchor {
                contract: ConnectivityContractRef::from_id([3; 32]),
                state: ContractState::Active,
                fresh_until_unix: contact.valid_until_tick,
                last_observed_at_unix: contact.at_tick.saturating_sub(10),
                last_sequence: 1,
                provider_node_id: [4; 32],
            },
            valid_until_unix: contact.valid_until_tick,
        }
    } else {
        GatewayAdmission::Ineligible {
            reasons: vec![
                AdmissionReason::ShareNetEvidenceMissing,
                AdmissionReason::AdcosEvidenceMissing,
            ],
        }
    };
    let budget = match ContactBudget::new(contact.max_bytes, contact.max_bundles) {
        Ok(budget) => budget,
        Err(err) => {
            stats.contacts_refused += 1;
            lines.push(format!(
                "CONTACT-REFUSED t={} node={} gw={} reason={}",
                contact.at_tick, contact.sender_tag, contact.gateway_tag, err.name()
            ));
            return;
        }
    };
    let closes = contact.at_tick + contact.duration;
    let window = match ContactOpportunity::new(
        node_id(contact.gateway_tag),
        &verdict,
        contact.at_tick,
        closes,
        budget,
    ) {
        Ok(window) => window,
        Err(err) => {
            stats.contacts_refused += 1;
            lines.push(format!(
                "CONTACT-REFUSED t={} node={} gw={} reason={}",
                contact.at_tick, contact.sender_tag, contact.gateway_tag, err.name()
            ));
            return;
        }
    };
    let now = contact.plan_clock.unwrap_or(contact.at_tick);
    // Plan (the sending edge) — a pure decision over the sender's own
    // image. The borrow is scoped: the per-step handover below takes
    // the map mutably (receiver) and immutably (sender) in turns.
    let plan_verdict = {
        let sender = nodes
            .get(&contact.sender_tag)
            .expect("scenario scripts existing nodes");
        forwarder.plan(&window, &sender.image, now)
    };
    match plan_verdict {
        ForwardVerdict::NothingToForward => {
            stats.nothing_to_forward += 1;
            lines.push(format!(
                "NOTHING t={now} node={} gw={}",
                contact.sender_tag, contact.gateway_tag
            ));
        }
        ForwardVerdict::Refused(refusal) => {
            stats.plan_refusals += 1;
            lines.push(format!(
                "PLAN-REFUSED t={now} node={} gw={} reason={}",
                contact.sender_tag, contact.gateway_tag, refusal.name()
            ));
        }
        ForwardVerdict::Plan(plan) => {
            stats.plans += 1;
            lines.push(format!(
                "PLAN t={now} node={} gw={} steps={} deferred={} bytes={}",
                contact.sender_tag,
                contact.gateway_tag,
                plan.steps().len(),
                plan.deferred().len(),
                plan.planned_bytes()
            ));
            // The deferrals, in carry order (typed and visible).
            for deferred in plan.deferred() {
                stats.deferred += 1;
                lines.push(format!(
                    "DEFER t={now} node={} content={} reason={}",
                    contact.sender_tag,
                    short_hex(deferred.content_id()),
                    deferred.reason().name()
                ));
            }
            // Each step, in carry order: move the material through
            // BOTH edges.
            for step in plan.steps() {
                stats.steps += 1;
                lines.push(format!(
                    "STEP t={now} node={} gw={} content={} priority={} expires={} cost={} slots={}",
                    contact.sender_tag,
                    contact.gateway_tag,
                    short_hex(step.content_id()),
                    step.priority(),
                    step.expires_at_unix(),
                    step.byte_cost(),
                    step.slots().len()
                ));
                // The sender's material, read through the store's own
                // image APIs + the carried bytes (the image holds
                // custody facts; the bytes are the session's). The
                // borrow is scoped to the reads.
                let id = *step.content_id();
                let (manifest_bytes, chunks) = {
                    let sender = nodes
                        .get(&contact.sender_tag)
                        .expect("scenario scripts existing nodes");
                    let manifest_bytes = sender
                        .image
                        .manifest_bytes(&id)
                        .expect("planned bundles are held")
                        .to_vec();
                    let chunks: Vec<(u32, Vec<u8>)> = step
                        .slots()
                        .iter()
                        .map(|slot| {
                            let bytes = sender
                                .carried
                                .get(&id)
                                .and_then(|slots| slots.get(slot))
                                .cloned()
                                .expect("planned slots are carried");
                            (*slot, bytes)
                        })
                        .collect();
                    (manifest_bytes, chunks)
                };
                // The receiving edge (R6-004): the gateway decides the
                // manifest offer, then the chunk offers.
                let sender_peer = node_peer(contact.sender_tag);
                let offer = ManifestOffer::new(
                    &manifest_bytes,
                    step.priority().as_str(),
                    step.expires_at_unix(),
                    step.summary().replication_target(),
                    &sender_peer,
                );
                let gateway = nodes
                    .get_mut(&contact.gateway_tag)
                    .expect("scenario scripts existing nodes");
                let manifest_verdict =
                    match receiving.take_custody(&mut gateway.image, &offer, now) {
                        Ok(verdict) => verdict,
                        Err(err) => {
                            // A store failure at the receiving edge —
                            // fail-closed: nothing landed.
                            stats.handovers_refused += 1;
                            lines.push(format!(
                                "HANDOVER-REFUSED t={now} gw={} content={} reason={}",
                                contact.gateway_tag,
                                short_hex(&id),
                                err.name()
                            ));
                            continue;
                        }
                    };
                let landed = !matches!(manifest_verdict, ManifestVerdict::Refused(_));
                let (ok, dup, refused) = if landed {
                    let mut ok = 0u64;
                    let mut dup = 0u64;
                    let mut refused = 0u64;
                    for (slot, bytes) in &chunks {
                        let chunk_offer = ChunkOffer::new(id, *slot as usize, bytes);
                        match receiving.receive_chunk(&mut gateway.image, &chunk_offer, now) {
                            Ok(verdict) if verdict.is_accept() => {
                                ok += 1;
                                gateway
                                    .carried
                                    .entry(id)
                                    .or_default()
                                    .insert(*slot, bytes.clone());
                            }
                            Ok(_) => dup += 1,
                            Err(_) => refused += 1,
                        }
                    }
                    (ok, dup, refused)
                } else {
                    (0, 0, 0)
                };
                lines.push(format!(
                    "RECEIVE t={now} gw={} content={} verdict={} chunks={ok}/{dup}/{refused}",
                    contact.gateway_tag,
                    short_hex(&id),
                    manifest_verdict.name()
                ));
                if !landed {
                    stats.handovers_refused += 1;
                    lines.push(format!(
                        "HANDOVER-REFUSED t={now} gw={} content={} reason={}",
                        contact.gateway_tag,
                        short_hex(&id),
                        manifest_verdict
                            .refusal()
                            .map(|r| r.name())
                            .unwrap_or("unknown")
                    ));
                    continue;
                }
                // The handover landed: the sender notes exactly one
                // forward for this gateway (evidence + the count).
                let sender = nodes
                    .get_mut(&contact.sender_tag)
                    .expect("scenario scripts existing nodes");
                sender
                    .image
                    .note_forwarded(&id, now, &node_peer(contact.gateway_tag))
                    .expect("planned bundles are held");
                let count = sender
                    .image
                    .summary(&id)
                    .expect("held")
                    .replication_count();
                stats.handovers_landed += 1;
                lines.push(format!(
                    "FORWARDED t={now} node={} gw={} content={} count={count}",
                    contact.sender_tag,
                    contact.gateway_tag,
                    short_hex(&id)
                ));
            }
        }
    }
}

/// A node id from a one-byte tag (byte 0; the rest zero —
/// deterministic and readable).
fn node_id(tag: u8) -> [u8; GATEWAY_ID_LEN] {
    let mut id = [0u8; GATEWAY_ID_LEN];
    id[0] = tag;
    id
}

/// A node's custody peer ref (the same bytes as its id — opaque
/// anyway).
fn node_peer(tag: u8) -> PeerRef {
    PeerRef::new(&node_id(tag)).expect("32 bytes fit the bound")
}

/// The first 8 bytes of an id as 16 hex chars (trace readability;
/// the full ids live in the world for assertions).
fn short_hex(id: &[u8]) -> String {
    sharenet_dtn::hex::encode(&id[..8])
}

// -------------------------------------------------------------------------
// The scenarios
// -------------------------------------------------------------------------

/// The scenario base tick (a fixed, deterministic epoch for every
/// scenario's clocks).
const T0: u64 = 1_700_000_000;

/// Seeded content: a manifest + its chunks, deterministic in
/// (rng, tag) — multi-chunk (12-byte chunks), a seeded size, a
/// seeded creation time.
fn seeded_content(rng: &mut SimRng, tag: u8) -> (ContentManifest, Vec<Vec<u8>>) {
    let len = 60 + rng.below(180) as usize; // 60..=239: multi-chunk
    let content: Vec<u8> = (0..len)
        .map(|i| tag.wrapping_mul(41).wrapping_add(i as u8).wrapping_add(rng.below(4) as u8))
        .collect();
    ContentManifest::chunk(&content, 12, "app/sim", None, T0 + rng.below(1_000)).expect("valid")
}

/// The three frozen priority names, in carry order.
const PRIORITY_NAMES: [&str; 3] = ["live", "opportunistic", "dtn"];

/// A partitioned node, holding a seeded stock of complete bundles
/// (mixed priorities, long TTLs, target 3), meets three intermittent
/// gateways in sparse windows — then the FIRST gateway again (which
/// must serve nothing more: one handover per bundle and gateway).
pub fn scenario_intermittent_gateway(seed: u64) -> SimScenario {
    let mut rng = SimRng::new(seed);
    let mut hero = SimNode::new(1);
    let genesis = node_peer(0);
    for i in 0..4u8 {
        let (manifest, chunks) = seeded_content(&mut rng, 0x30 + i);
        let priority =
            sharenet_dtn::ServicePriority::from_name(PRIORITY_NAMES[i as usize % 3]).unwrap();
        hero.seed_bundle(&manifest, &chunks, priority, T0, T0 + 50_000, 3, &genesis);
    }
    let mut events = Vec::new();
    // Three sparse windows, one per gateway (the node was partitioned
    // before T0+1_000: the first contact ever is the scenario's
    // start).
    for round in 0..3u8 {
        events.push(SimEvent::Contact(SimContact {
            at_tick: T0 + 1_000 + round as u64 * 1_000,
            sender_tag: 1,
            gateway_tag: 11 + round,
            duration: 50,
            max_bytes: 100_000,
            max_bundles: 10,
            valid_until_tick: T0 + 1_000 + round as u64 * 1_000 + 100,
            eligible: true,
            plan_clock: None,
        }));
    }
    // A fourth window with the FIRST gateway again: every bundle is
    // already handed to it — all deferrals must be `already_handed`.
    events.push(SimEvent::Contact(SimContact {
        at_tick: T0 + 4_000,
        sender_tag: 1,
        gateway_tag: 11,
        duration: 50,
        max_bytes: 100_000,
        max_bundles: 10,
        valid_until_tick: T0 + 4_100,
        eligible: true,
        plan_clock: None,
    }));
    SimScenario {
        name: "intermittent-gateway",
        seed,
        forwarder: ForwarderParams::default(),
        receiving: PropagationParams::default(),
        nodes: vec![hero, SimNode::new(11), SimNode::new(12), SimNode::new(13)],
        events,
    }
}

/// Expiry disruption: a bundle dead before any window, one dying
/// exactly inside a window, one below the remaining-life floor at the
/// close, and one healthy — only the healthy one is ever served; the
/// sweep evicts the dead.
pub fn scenario_expiry(seed: u64) -> SimScenario {
    let mut rng = SimRng::new(seed);
    let mut hero = SimNode::new(1);
    let genesis = node_peer(0);
    // A: healthy, long TTL, target 2 (two windows to serve it).
    let (a, a_chunks) = seeded_content(&mut rng, 0x40);
    hero.seed_bundle(&a, &a_chunks, sharenet_dtn::ServicePriority::Dtn, T0, T0 + 50_000, 2, &genesis);
    // B: dead before ANY window (expires at T0+500).
    let (b, b_chunks) = seeded_content(&mut rng, 0x41);
    hero.seed_bundle(&b, &b_chunks, sharenet_dtn::ServicePriority::Live, T0, T0 + 500, 1, &genesis);
    // C: dies INSIDE the first window (window [T0+1_000, T0+1_100),
    // C expires T0+1_050 — the hard gate defers it).
    let (c, c_chunks) = seeded_content(&mut rng, 0x42);
    hero.seed_bundle(&c, &c_chunks, sharenet_dtn::ServicePriority::Live, T0, T0 + 1_050, 1, &genesis);
    // D: dies just after the close (T0+1_150) — 50s of life at the
    // close is below the default 60s floor.
    let (d, d_chunks) = seeded_content(&mut rng, 0x43);
    hero.seed_bundle(&d, &d_chunks, sharenet_dtn::ServicePriority::Opportunistic, T0, T0 + 1_150, 1, &genesis);
    SimScenario {
        name: "expiry",
        seed,
        forwarder: ForwarderParams::default(),
        receiving: PropagationParams::default(),
        nodes: vec![hero, SimNode::new(11), SimNode::new(12)],
        events: vec![
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_000,
                sender_tag: 1,
                gateway_tag: 11,
                duration: 100,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_200,
                eligible: true,
                plan_clock: None,
            }),
            // The sweep after the window: B, C and D are expired by
            // now (A survives).
            SimEvent::Evict { at_tick: T0 + 2_000 },
            SimEvent::Contact(SimContact {
                at_tick: T0 + 3_000,
                sender_tag: 1,
                gateway_tag: 12,
                duration: 100,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 3_200,
                eligible: true,
                plan_clock: None,
            }),
        ],
    }
}

/// Tight budgets: six bundles of mixed priorities, one bundle per
/// window (count-bound 1) — the served order is the carry order
/// (live before opportunistic before dtn); a final byte-bound window
/// too small for anything serves nothing.
pub fn scenario_tight_budget(seed: u64) -> SimScenario {
    let mut rng = SimRng::new(seed);
    let mut hero = SimNode::new(1);
    let genesis = node_peer(0);
    // Two bundles per priority class, target 1 (one handover each).
    for i in 0..6u8 {
        let (manifest, chunks) = seeded_content(&mut rng, 0x50 + i);
        let priority =
            sharenet_dtn::ServicePriority::from_name(PRIORITY_NAMES[(i / 2) as usize]).unwrap();
        hero.seed_bundle(&manifest, &chunks, priority, T0, T0 + 50_000, 1, &genesis);
    }
    let mut events = Vec::new();
    // Six count-bound windows with one gateway: each round moves the
    // head of the remaining carry order.
    for round in 0..6u64 {
        events.push(SimEvent::Contact(SimContact {
            at_tick: T0 + 1_000 + round * 100,
            sender_tag: 1,
            gateway_tag: 11,
            duration: 50,
            max_bytes: 1_000_000,
            max_bundles: 1,
            valid_until_tick: T0 + 1_000 + round * 100 + 100,
            eligible: true,
            plan_clock: None,
        }));
    }
    // A byte-bound window too small for the smallest bundle: every
    // candidate defers `does_not_fit_budget`.
    events.push(SimEvent::Contact(SimContact {
        at_tick: T0 + 2_000,
        sender_tag: 1,
        gateway_tag: 12,
        duration: 50,
        max_bytes: 1,
        max_bundles: 10,
        valid_until_tick: T0 + 2_100,
        eligible: true,
        plan_clock: None,
    }));
    SimScenario {
        name: "tight-budget",
        seed,
        forwarder: ForwarderParams::default(),
        receiving: PropagationParams::default(),
        nodes: vec![hero, SimNode::new(11), SimNode::new(12)],
        events,
    }
}

/// Ineligible gateways and bad clocks: an ineligible verdict, a
/// window that outlives its evidence, a plan clock before the window
/// and one after — all typed refusals, nothing moves — then a clean
/// contact serves everything.
pub fn scenario_ineligible_gateway(seed: u64) -> SimScenario {
    let mut rng = SimRng::new(seed);
    let mut hero = SimNode::new(1);
    let genesis = node_peer(0);
    for i in 0..2u8 {
        let (manifest, chunks) = seeded_content(&mut rng, 0x60 + i);
        hero.seed_bundle(&manifest, &chunks, sharenet_dtn::ServicePriority::Dtn, T0, T0 + 50_000, 1, &genesis);
    }
    SimScenario {
        name: "ineligible-gateway",
        seed,
        forwarder: ForwarderParams::default(),
        receiving: PropagationParams::default(),
        nodes: vec![hero, SimNode::new(11), SimNode::new(12), SimNode::new(13), SimNode::new(14)],
        events: vec![
            // Ineligible: construction refused typed.
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_000,
                sender_tag: 1,
                gateway_tag: 11,
                duration: 50,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_100,
                eligible: false,
                plan_clock: None,
            }),
            // Window outlives the evidence (close T0+1_150 > bound
            // T0+1_100): construction refused typed.
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_200,
                sender_tag: 1,
                gateway_tag: 12,
                duration: 150,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_300,
                eligible: true,
                plan_clock: None,
            }),
            // Plan clock BEFORE the window: typed refusal.
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_400,
                sender_tag: 1,
                gateway_tag: 13,
                duration: 100,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_600,
                eligible: true,
                plan_clock: Some(T0 + 1_399),
            }),
            // Plan clock AT the close (exclusive): typed refusal.
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_400,
                sender_tag: 1,
                gateway_tag: 13,
                duration: 100,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_600,
                eligible: true,
                plan_clock: Some(T0 + 1_500),
            }),
            // The clean contact: everything moves.
            SimEvent::Contact(SimContact {
                at_tick: T0 + 2_000,
                sender_tag: 1,
                gateway_tag: 14,
                duration: 100,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 2_200,
                eligible: true,
                plan_clock: None,
            }),
        ],
    }
}

/// Edge floors: the sender's floor disabled, the receiver's at the
/// default 60s — a bundle with 55s of life at the receiver's clock
/// is planned by the sender but REFUSED at the receiving edge (typed,
/// R6-004), and the sender honestly notes nothing for it.
pub fn scenario_edge_floors(seed: u64) -> SimScenario {
    let mut rng = SimRng::new(seed);
    let mut hero = SimNode::new(1);
    let genesis = node_peer(0);
    // X: 55s of life at the window clock (T0+1_000) — the sender
    // (floor disabled) plans it; the receiver (floor 60) refuses.
    let (x, x_chunks) = seeded_content(&mut rng, 0x70);
    hero.seed_bundle(&x, &x_chunks, sharenet_dtn::ServicePriority::Live, T0, T0 + 1_055, 2, &genesis);
    // Y: healthy, target 2.
    let (y, y_chunks) = seeded_content(&mut rng, 0x71);
    hero.seed_bundle(&y, &y_chunks, sharenet_dtn::ServicePriority::Dtn, T0, T0 + 50_000, 2, &genesis);
    SimScenario {
        name: "edge-floors",
        seed,
        // The sending edge's floor is OFF (only the hard gate
        // remains) — the receiving edge keeps the default 60s, so
        // the composed pipeline proves where the floor bites.
        forwarder: ForwarderParams::new(0),
        receiving: PropagationParams::default(),
        nodes: vec![hero, SimNode::new(11), SimNode::new(12)],
        events: vec![
            SimEvent::Contact(SimContact {
                at_tick: T0 + 1_000,
                sender_tag: 1,
                gateway_tag: 11,
                duration: 10,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 1_100,
                eligible: true,
                plan_clock: None,
            }),
            // Long after X's death: only Y remains (its second
            // handover — target 2).
            SimEvent::Contact(SimContact {
                at_tick: T0 + 3_000,
                sender_tag: 1,
                gateway_tag: 12,
                duration: 50,
                max_bytes: 100_000,
                max_bundles: 10,
                valid_until_tick: T0 + 3_100,
                eligible: true,
                plan_clock: None,
            }),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rng is deterministic and seed-sensitive.
    #[test]
    fn rng_is_deterministic_and_seeded() {
        let mut a = SimRng::new(42);
        let mut b = SimRng::new(42);
        let mut c = SimRng::new(43);
        for _ in 0..16 {
            let x = a.next_u64();
            assert_eq!(x, b.next_u64());
            assert_ne!(x, c.next_u64());
        }
        assert_eq!(SimRng::new(0).below(1), 0);
        assert!(SimRng::new(7).below(10) < 10);
    }

    /// Node ids and peers are tag-derived and stable.
    #[test]
    fn node_ids_are_tag_derived() {
        assert_eq!(node_id(1), {
            let mut id = [0u8; 32];
            id[0] = 1;
            id
        });
        assert_eq!(node_peer(9).as_bytes(), &node_id(9));
    }
}
