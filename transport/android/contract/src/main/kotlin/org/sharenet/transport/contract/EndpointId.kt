package org.sharenet.transport.contract

/**
 * Identifier of a remote endpoint as presented by the local transport.
 *
 * Opaque at the contract level: transports are free to derive it from their
 * platform identifiers (Nearby endpoint ids, Wi-Fi Aware peers, ...). It
 * carries no ShareNet protocol identity — authenticated link identity is
 * protocol-core scope (R3-001), not transport scope.
 */
@JvmInline
value class EndpointId(val value: String) {
    override fun toString(): String = value
}
