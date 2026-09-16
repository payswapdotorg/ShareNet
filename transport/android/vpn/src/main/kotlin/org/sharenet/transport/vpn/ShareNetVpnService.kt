package org.sharenet.transport.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Production caller skeleton (R4-004): the Android `VpnService` the
 * future ShareNet app embeds to bring device traffic into the tunnel.
 *
 * Division of labor (the whole point of this module's design):
 *  * EVERYTHING testable on the JVM is extracted and unit-tested:
 *    [VpnConfig] strict validation, [VpnConfig.toBuilderParams],
 *    [IpPacketFilter], and the [PacketLoop] (driven over a pipe-backed
 *    [PacketIO] by an echo [TunnelBackhaul] in tests).
 *  * The remaining Android glue in THIS class is mechanical wiring —
 *    the 1:1 Builder mapping, the fd handoff, thread + lifecycle
 *    plumbing — and is NOT unit-testable without a device (android.jar
 *    methods fail under the JVM unit-test runner by design; this wave
 *    has no physical device). On-device verification is R10-002 scope.
 *
 * Embedding flow (future app):
 * ```kotlin
 * // 1. consent (app side, on the main thread)
 * val consent = VpnService.prepare(context)
 * if (consent != null) startActivityForResult(consent, REQUEST)
 * // 2. skeleton wiring: the JNI backhaul IS R10-002 (JniTunnelBackhaul)
 * ShareNetVpnService.configureBackhaul { jniBackhaul() }
 * // 3. start
 * context.startService(Intent(context, ShareNetVpnService::class.java).apply {
 *     action = ShareNetVpnService.ACTION_START
 *     putExtra(ShareNetVpnService.EXTRA_SESSION_NAME, "sharenet-bridge")
 *     putStringArrayListExtra(ShareNetVpnService.EXTRA_ADDRESSES, arrayListOf("10.111.111.2/32", "fd00::2/128"))
 *     putStringArrayListExtra(ShareNetVpnService.EXTRA_ROUTES, arrayListOf("0.0.0.0/0", "::/0"))
 * })
 * ```
 *
 * Persistence: none — the service keeps only the live loop, thread, and
 * descriptor. Reconfigure = stop + start with a new config.
 */
class ShareNetVpnService : VpnService() {

    companion object {
        private const val TAG = "ShareNetVpn"

        /** Establish the interface and start the packet loop. */
        const val ACTION_START = "org.sharenet.transport.vpn.action.START"

        /** Stop the loop and tear the interface down. */
        const val ACTION_STOP = "org.sharenet.transport.vpn.action.STOP"

        /** String extra for [ACTION_START]: session name (default "sharenet"). */
        const val EXTRA_SESSION_NAME = "session_name"

        /** StringArrayList extra for [ACTION_START]: interface addresses (required, non-empty). */
        const val EXTRA_ADDRESSES = "addresses"

        /** StringArrayList extra for [ACTION_START]: routed networks. */
        const val EXTRA_ROUTES = "routes"

        /** StringArrayList extra for [ACTION_START]: tunnel DNS servers. */
        const val EXTRA_DNS_SERVERS = "dns_servers"

        /** StringArrayList extra for [ACTION_START]: app packages per the filter mode. */
        const val EXTRA_APP_PACKAGES = "app_packages"

        /** String extra for [ACTION_START]: "ALLOWLIST" or "BLOCKLIST" (default "BLOCKLIST"). */
        const val EXTRA_APP_FILTER_MODE = "app_filter_mode"

        /** Int extra for [ACTION_START]: MTU (default [VpnConfig.DEFAULT_MTU]). */
        const val EXTRA_MTU = "mtu"

        private const val DEFAULT_SESSION_NAME = "sharenet"
        private const val MODE_ALLOWLIST = "ALLOWLIST"
        private const val MODE_BLOCKLIST = "BLOCKLIST"

        /**
         * Wiring point for the tunnel seam: the embedding app installs
         * the backhaul factory at startup — R10-002's production wiring
         * is `JniTunnelBackhaul(LoadedBridgeNative, seed, gatewayAddr,
         * gatewayNodeHex)` (see README.md §The JNI bridge for the NDK
         * build runbook). Until a factory is installed, [ACTION_START]
         * logs a typed error and stays down — the service never starts
         * a loop with no backhaul.
         */
        @Volatile
        private var backhaulFactory: (() -> TunnelBackhaul)? = null

        /** Install the [TunnelBackhaul] factory (idempotent overwrite). */
        fun configureBackhaul(factory: () -> TunnelBackhaul) {
            backhaulFactory = factory
        }
    }

    private var loop: PacketLoop? = null
    private var loopThread: Thread? = null
    private var tun: PacketIO? = null

    /**
     * Establish the TUN interface for [config].
     *
     * The Builder configuration is computed PURELY and unit-tested via
     * [VpnConfig.toBuilderParams]; this method only performs the
     * mechanical 1:1 mapping onto `VpnService.Builder` plus
     * `establish()` — the device-only part (R10-002).
     *
     * @throws VpnError.InvalidConfig if [config] fails validation
     *         (re-thrown from the pure layer).
     * @throws VpnError.VpnNotPrepared if the platform refuses to
     *         establish (consent missing/revoked).
     */
    fun buildInterface(config: VpnConfig): ParcelFileDescriptor {
        val params = config.toBuilderParams()
        val builder = Builder()
        builder.setSession(params.sessionName)
        builder.setMtu(params.mtu)
        for (address in params.addresses) {
            builder.addAddress(address.address.text, address.prefixLength)
        }
        for (route in params.routes) {
            builder.addRoute(route.address.text, route.prefixLength)
        }
        for (dns in params.dnsServers) {
            builder.addDnsServer(dns.text)
        }
        when (val filter = params.appFilter) {
            is AppFilter.Allowlist -> for (pkg in filter.packages) builder.addAllowedApplication(pkg)
            is AppFilter.Blocklist -> for (pkg in filter.packages) builder.addDisallowedApplication(pkg)
        }
        // Blocking mode: the loop thread's reads/writes block instead of
        // returning EAGAIN — matches PacketIO's blocking contract.
        builder.setBlocking(true)
        return builder.establish() ?: throw VpnError.VpnNotPrepared()
    }

    /**
     * Start the production packet loop on [fd].
     *
     * Wraps the descriptor in [FdPacketIo], builds the [PacketLoop], and
     * runs it on a dedicated thread (the loop never touches the main
     * thread). Returns the loop handle for graceful [PacketLoop.stop].
     *
     * @throws VpnError.InvalidConfig if [mtu] is out of bounds (typed
     *         re-throw from the loop's constructor validation).
     */
    fun startPacketLoop(fd: ParcelFileDescriptor, mtu: Int, backhaul: TunnelBackhaul): PacketLoop {
        val io = FdPacketIo(fd)
        val packetLoop = PacketLoop(io, mtu, backhaul)
        val thread = Thread(packetLoop::run, "ShareNetVpnPacketLoop").apply {
            isDaemon = true
            start()
        }
        synchronized(this) {
            check(loop == null) { "packet loop already started" }
            tun = io
            loop = packetLoop
            loopThread = thread
        }
        return packetLoop
    }

    /**
     * Graceful teardown: stop flag first, then close the descriptor —
     * the close unblocks a pending read (EOF), the flag guarantees no
     * packet is forwarded after the stop is requested.
     */
    private fun stopLoop() {
        val (currentLoop, currentIo) = synchronized(this) {
            val pair = loop to tun
            loop = null
            tun = null
            loopThread = null
            pair
        }
        currentLoop?.stop()
        currentIo?.close()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart(intent)
            ACTION_STOP -> stopLoop()
            else -> Log.w(TAG, "ignoring unknown action ${intent?.action}")
        }
        // Not sticky: a restart without an intent would have no backhaul
        // or config to resume (session state is transient by design).
        return START_NOT_STICKY
    }

    private fun handleStart(intent: Intent) {
        val factory = backhaulFactory
        if (factory == null) {
            // Typed failure, not a crash — the app forgot the skeleton wiring.
            Log.e(TAG, "no backhaul configured: call ShareNetVpnService.configureBackhaul first (R10-002 installs the JNI bridge)")
            return
        }
        val config = configFrom(intent)
        try {
            stopLoop() // reconfigure = restart
            val fd = buildInterface(config)
            val packetLoop = startPacketLoop(fd, config.mtu, factory())
            Log.i(TAG, "vpn up: ${config.sessionName} mtu=${config.mtu} loop=${packetLoop.stats}")
        } catch (e: VpnError) {
            // Typed VPN errors are service-level events, not crashes
            // (bad config from the app, or consent not granted).
            Log.w(TAG, "vpn start failed: $e")
        }
    }

    private fun configFrom(intent: Intent): VpnConfig = VpnConfig(
        sessionName = intent.getStringExtra(EXTRA_SESSION_NAME) ?: DEFAULT_SESSION_NAME,
        addresses = intent.getStringArrayListExtra(EXTRA_ADDRESSES).orEmpty(),
        routes = intent.getStringArrayListExtra(EXTRA_ROUTES).orEmpty(),
        dnsServers = intent.getStringArrayListExtra(EXTRA_DNS_SERVERS).orEmpty(),
        appPackages = intent.getStringArrayListExtra(EXTRA_APP_PACKAGES).orEmpty(),
        appFilterMode = when (intent.getStringExtra(EXTRA_APP_FILTER_MODE)) {
            null, MODE_BLOCKLIST -> AppFilterMode.BLOCKLIST
            MODE_ALLOWLIST -> AppFilterMode.ALLOWLIST
            else -> {
                Log.w(TAG, "unknown ${EXTRA_APP_FILTER_MODE}; defaulting to BLOCKLIST")
                AppFilterMode.BLOCKLIST
            }
        },
        mtu = if (intent.hasExtra(EXTRA_MTU)) intent.getIntExtra(EXTRA_MTU, VpnConfig.DEFAULT_MTU) else VpnConfig.DEFAULT_MTU,
    )

    /** The system revoked VPN consent (user pressed the VPN toggle). */
    override fun onRevoke() {
        Log.w(TAG, "vpn revoked by user/system; tearing down")
        stopLoop()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopLoop()
        Log.i(TAG, "vpn service destroyed")
        super.onDestroy()
    }

}
