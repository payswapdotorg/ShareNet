# ADCOS Integration Contract

## Authority

ADCOS Architecture 1.1 is authoritative for the external connectivity layer.

The canonical durable object is:

    ConnectivityContract

ShareNet stores:

    ConnectivityContractRef
    optional lease/reference data
    signed observations
    local health projection

ShareNet MUST NOT recreate ADCOS contract semantics.

## Interface

```text
interface ConnectivityPort {
    createIntent(requirement): ConnectivityIntentRef
    discoverOffers(intent): ConnectivityOfferRef[]
    acceptOffer(intent, offer): ConnectivityContractRef
    getContract(contract): ConnectivityContractProjection
    getAssurance(contract): ConnectivityObservation[]
    getExecution(contract): ConnectivityExecutionProjection
    terminate(contract): void
}
```

The actual wire client speaks the ADCOS developer API. The domain does not import ADCOS server internals.

## Event mapping

ADCOS observations:

- contract activated;
- execution state changed;
- degraded;
- assurance available;
- failover/replan;
- terminated.

are mapped into a ShareNet operational projection.

An observation is not permitted to mutate ShareNet's authoritative circuit, route, identity or content state without independent ShareNet protocol verification.

## Gateway admission

A gateway becomes ShareNet-eligible only when BOTH exist:

1. authenticated ShareNet node/link evidence;
2. acceptable ADCOS-backed external connectivity evidence.

ADCOS does not attest ShareNet packet delivery.

ShareNet does not attest provider fulfillment.

## Failure semantics

If ADCOS is unavailable:

- do not destroy valid local P2P state solely because of the outage;
- do not fabricate a contract state;
- cache the last accepted observation with freshness metadata;
- prevent new acquisition if authorization cannot be established;
- continue local/DTN operations.

## Provider isolation

Forbidden imports:

```text
provider-native SDK
gNB API
UPF API
carrier SDK
Wi-Fi operator proprietary API
IPsec/tunnel provider object
```

inside ShareNet protocol core or `connectivity/` domain.

Only the ADCOS adapter may know the ADCOS developer API transport format.

## Why this division exists

ADCOS sells/allocates connectivity outcomes. ShareNet consumes those outcomes to create authenticated connectivity paths and deliver Internet/content/service to peers.

The two systems are complementary, not merged.
