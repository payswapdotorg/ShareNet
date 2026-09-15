package org.sharenet.transport.vpn

/**
 * Typed VPN data-plane errors (R4-004).
 *
 * NO platform types leak here — the service boundary classifies its native
 * failures into these. All validation in this module is STRICT: invalid
 * input is rejected with a typed error, never silently defaulted.
 */
sealed class VpnError(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /**
     * A [VpnConfig] (or loop parameter) field failed strict validation.
     *
     * @param field the offending field path (e.g. `"routes[1]"`, `"mtu"`).
     * @param reason human-readable, test-asserted explanation.
     */
    class InvalidConfig(
        val field: String,
        val reason: String,
    ) : VpnError("invalid vpn config field '$field': $reason")

    /** A packet exceeded the size bound (larger than the MTU buffer). */
    class PacketTooLarge(
        val size: Int,
        val maxBytes: Int,
    ) : VpnError("packet of $size bytes exceeds the $maxBytes-byte bound")

    /** The tunnel backhaul failed; the packet loop stops (fails closed). */
    class BackhaulFailure(
        cause: Throwable,
        message: String = "tunnel backhaul failure",
    ) : VpnError(message, cause)

    /** An I/O failure on the TUN descriptor; the packet loop stops. */
    class IoFailure(
        cause: Throwable,
        message: String = "tun i/o failure",
    ) : VpnError(message, cause)

    /**
     * The platform refused to establish the interface (typically: the user
     * has not granted VPN consent, or the service was revoked). Raised by
     * `ShareNetVpnService.buildInterface` when `establish()` returns null.
     */
    class VpnNotPrepared(
        message: String =
            "vpn interface not established (consent missing, revoked, or the service is not prepared)",
    ) : VpnError(message)
}
