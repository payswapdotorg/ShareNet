package org.sharenet.transport.vpn

/**
 * THE R10-002 PRODUCTION BACKHAUL: [TunnelBackhaul] over the Rust
 * bridge (`transport/android-bridge`, JNI).
 *
 * One instance = one participant session (pinned QUIC tunnel + R4-002
 * circuit admission + the R4-003 data plane — the exact session the
 * R10-001 two-process loopback proved). The mapping follows the seam's
 * own contract:
 *
 *  * [forward] may block (network I/O), is called once per
 *    filter-accepted packet on the loop thread, and returns the
 *    response packets in write order;
 *  * ANY failure is a TUNNEL FAILURE — rethrown as a typed
 *    [VpnError.BackhaulFailure] so the loop fails closed (a half-dead
 *    VPN that silently swallows traffic is worse than a visible dead
 *    one);
 *  * [close] destroys the circuit exactly once (terminal BYE) and
 *    neutralizes the handle — a forward after close fails closed.
 */
class JniTunnelBackhaul(
    private val library: BridgeNativeLibrary,
    seed: ByteArray,
    private val gatewayAddr: String,
    private val gatewayNodeHex: String,
    idleMs: Long = DEFAULT_IDLE_MS,
) : TunnelBackhaul, AutoCloseable {

    private var handle: Long

    init {
        require(seed.size == IDENTITY_SEED_BYTES) {
            "identity seed must be exactly $IDENTITY_SEED_BYTES bytes, got ${seed.size}"
        }
        require(gatewayNodeHex.length == NODE_ID_HEX_CHARS) {
            "gateway node id must be $NODE_ID_HEX_CHARS hex chars, got ${gatewayNodeHex.length}"
        }
        require(idleMs >= MIN_IDLE_MS) { "idle timeout must be >= $MIN_IDLE_MS ms" }
        val version = try {
            library.nativeVersion()
        } catch (t: Throwable) {
            throw VpnError.BackhaulFailure(
                t,
                "the ShareNet bridge library is unavailable (loadLibrary failed)",
            )
        }
        if (version != BridgeApiVersion.EXPECTED) {
            throw VpnError.BackhaulFailure(
                IllegalStateException("bridge ABI version $version != ${BridgeApiVersion.EXPECTED}"),
                "ShareNet bridge ABI mismatch — rebuild libsharenet_bridge.so",
            )
        }
        handle = try {
            library.nativeOpen(seed.copyOf(), gatewayAddr, gatewayNodeHex, idleMs)
        } catch (t: Throwable) {
            throw VpnError.BackhaulFailure(t, "bridge session open failed for $gatewayAddr")
        }
        if (handle == 0L) {
            throw VpnError.BackhaulFailure(
                IllegalStateException("nativeOpen returned a null handle for $gatewayAddr"),
            )
        }
    }

    override fun forward(packet: ByteArray): List<ByteArray> {
        val current = handle
        if (current == 0L) {
            throw VpnError.BackhaulFailure(
                IllegalStateException("bridge session already closed"),
                "bridge session already closed",
            )
        }
        val responses = try {
            library.nativeForward(current, packet)
        } catch (t: Throwable) {
            throw VpnError.BackhaulFailure(t, "bridge forward failed")
        }
        if (responses == null) {
            throw VpnError.BackhaulFailure(
                IllegalStateException("nativeForward failed (exception pending on the JNI side)"),
            )
        }
        return responses.toList()
    }

    /** Destroy the circuit (terminal). Exactly-once; idempotent. */
    override fun close() {
        val current = handle
        if (current != 0L) {
            handle = 0L
            try {
                library.nativeDestroy(current, "completed")
            } catch (t: Throwable) {
                // Fail closed on the session state (the handle is gone
                // either way) but surface the failure — a silently
                // half-destroyed circuit would leak gateway state.
                throw VpnError.BackhaulFailure(t, "bridge destroy failed")
            }
        }
    }

    companion object {
        /** 32 bytes (the R1-001 identity seed law). */
        const val IDENTITY_SEED_BYTES = 32

        /** 64 hex chars (the 32-byte node id). */
        const val NODE_ID_HEX_CHARS = 64

        /**
         * The bounded idle timeout default (30 s) — a silently dead
         * gateway errors the blocked reads after this window (the
         * R10-001 failure-detection idiom), instead of hanging the
         * loop thread forever.
         */
        const val DEFAULT_IDLE_MS: Long = 30_000L

        /** The bridge's own minimum (must be >= 100 ms). */
        const val MIN_IDLE_MS: Long = 100L
    }
}
