package org.sharenet.transport.vpn

/**
 * THE RUST BRIDGE SURFACE (R10-002) — the JNI functions exported by
 * `transport/android-bridge` (`libsharenet_bridge.so`, built with
 * cargo-ndk — see vpn/README.md §The JNI bridge for the operator
 * runbook).
 *
 * Symbol names are ABI-frozen on the Rust side
 * (`Java_org_sharenet_transport_vpn_BridgeNative_native*`); this
 * object declares the matching `external fun`s. [BridgeNativeLibrary]
 * is the injectable seam the JVM tests fake — the external functions
 * need the NDK-built library, deliberately absent from the JVM unit
 * sandbox (the same discipline as R4-004's FakeTunnelBackhaul).
 */
object BridgeNative {

    /** Loads the NDK-built library; fails closed if absent. */
    fun ensureLoaded() {
        System.loadLibrary("sharenet_bridge")
    }

    /** The bridge ABI version (must equal [BridgeApiVersion.EXPECTED]). */
    external fun nativeVersion(): Int

    /**
     * Open one participant session (pinned QUIC tunnel + circuit
     * admission + the R4-003 data plane).
     *
     * @param seed exactly 32 identity seed bytes.
     * @param gatewayAddr the gateway's tunnel address (host:port).
     * @param gatewayNodeHex the PINNED gateway node id (64 hex chars —
     *        the id the service discovered, never a hardcoded one).
     * @param idleMs the bounded idle timeout (>= 100; a silently dead
     *        gateway errors the blocked reads instead of hanging the
     *        loop thread — the R10-001 failure-detection idiom).
     * @return the opaque session handle (0 = failure, with the typed
     *         Java exception set).
     */
    external fun nativeOpen(
        seed: ByteArray,
        gatewayAddr: String,
        gatewayNodeHex: String,
        idleMs: Long,
    ): Long

    /**
     * Forward one complete, filter-accepted packet; returns the
     * response packets in write order. May block (network I/O). Loop
     * thread only (the seam contract).
     *
     * @return the responses as `[[B` (null = failure, exception set).
     */
    external fun nativeForward(handle: Long, packet: ByteArray): Array<ByteArray>?

    /**
     * Destroy the session (terminal; consumes the handle exactly
     * once). Returns true on success.
     */
    external fun nativeDestroy(handle: Long, reason: String): Boolean
}

/** The bridge ABI version contract (checked after loadLibrary). */
object BridgeApiVersion {
    /** The version THIS Kotlin surface is written against. */
    const val EXPECTED: Int = 1
}

/**
 * The injectable library seam: production wires [BridgeNative]; JVM
 * tests inject a fake — external functions cannot run without the
 * NDK-built .so, and the JVM sandbox has none (honest scope, R10-002).
 */
interface BridgeNativeLibrary {
    fun nativeVersion(): Int

    fun nativeOpen(
        seed: ByteArray,
        gatewayAddr: String,
        gatewayNodeHex: String,
        idleMs: Long,
    ): Long

    fun nativeForward(handle: Long, packet: ByteArray): Array<ByteArray>?

    fun nativeDestroy(handle: Long, reason: String): Boolean
}

/** The production library binding (loads the .so exactly once). */
object LoadedBridgeNative : BridgeNativeLibrary {

    @Volatile
    private var loaded = false

    private fun ensureLoaded() {
        if (!loaded) {
            synchronized(this) {
                if (!loaded) {
                    BridgeNative.ensureLoaded()
                    loaded = true
                }
            }
        }
    }

    override fun nativeVersion(): Int {
        ensureLoaded()
        return BridgeNative.nativeVersion()
    }

    override fun nativeOpen(
        seed: ByteArray,
        gatewayAddr: String,
        gatewayNodeHex: String,
        idleMs: Long,
    ): Long {
        ensureLoaded()
        return BridgeNative.nativeOpen(seed, gatewayAddr, gatewayNodeHex, idleMs)
    }

    override fun nativeForward(handle: Long, packet: ByteArray): Array<ByteArray>? {
        ensureLoaded()
        return BridgeNative.nativeForward(handle, packet)
    }

    override fun nativeDestroy(handle: Long, reason: String): Boolean {
        ensureLoaded()
        return BridgeNative.nativeDestroy(handle, reason)
    }
}
