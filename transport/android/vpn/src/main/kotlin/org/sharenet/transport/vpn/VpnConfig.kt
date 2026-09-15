package org.sharenet.transport.vpn

/** How [VpnConfig.appPackages] is applied by the platform Builder. */
enum class AppFilterMode {
    /** ONLY the listed packages are routed through the VPN. */
    ALLOWLIST,

    /** All packages EXCEPT the listed ones are routed through the VPN. */
    BLOCKLIST,
}

/** Validated, mode-resolved application filter (from [VpnConfig.toBuilderParams]). */
sealed class AppFilter {
    /** Route only [packages] through the tunnel (non-empty by validation). */
    data class Allowlist(val packages: List<String>) : AppFilter()

    /** Route everything except [packages] (empty = all apps). */
    data class Blocklist(val packages: List<String>) : AppFilter()
}

/**
 * Everything `VpnService.Builder` needs, derived PURELY (no platform
 * types) from a validated [VpnConfig]. The Android call site in
 * `ShareNetVpnService.buildInterface` is a mechanical 1:1 mapping of
 * these fields onto Builder methods — kept minimal and untested on the
 * JVM (no device in this wave; R10-002 owns on-device verification).
 */
data class BuilderParams(
    val sessionName: String,
    val mtu: Int,
    /** Interface addresses (at least one; Builder refuses to establish without). */
    val addresses: List<Cidr>,
    /** Routed networks (clean network prefixes — no host bits, validated). */
    val routes: List<Cidr>,
    val dnsServers: List<IpAddress>,
    val appFilter: AppFilter,
)

/**
 * Strict VPN interface configuration (R4-004).
 *
 * Validation is TOTAL and TYPED: [validate] (and therefore
 * [toBuilderParams]) throws [VpnError.InvalidConfig] on the FIRST
 * invalid field — there are no silent defaults for invalid input. The
 * only defaults are the documented ones: [mtu] 1280, [dnsServers] empty
 * (no tunnel DNS), [appPackages] empty with [AppFilterMode.BLOCKLIST]
 * (all apps routed — the bridge-the-Internet mission's default shape).
 *
 * @property sessionName shown in the system VPN banner.
 * @property addresses interface addresses; `ip` or `ip/prefix` (a bare IP
 *           means a host route: /32 v4, /128 v6). Non-empty.
 * @property routes routed networks; STRICT `ip/prefix` CIDR — a missing
 *           prefix or host bits below the prefix is rejected.
 * @property dnsServers plain IP literals (any prefix form is rejected).
 * @property appPackages Android package names, interpreted per
 *           [appFilterMode].
 * @property mtu interface MTU, bounded [MIN_MTU]..[MAX_MTU].
 */
data class VpnConfig(
    val sessionName: String,
    val addresses: List<String>,
    val routes: List<String> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val appPackages: List<String> = emptyList(),
    val appFilterMode: AppFilterMode = AppFilterMode.BLOCKLIST,
    val mtu: Int = DEFAULT_MTU,
) {
    companion object {
        /** RFC 791 minimum IPv4 datagram we are willing to carry. */
        const val MIN_MTU = 68

        /** IPv4 total-length field is 16 bits. */
        const val MAX_MTU = 65_535

        /** IPv6-unfriendly-but-IPv4-safe default (RFC 8200 recommends 1280). */
        const val DEFAULT_MTU = 1_280

        /** Our conservative bound for a package name (Android's own limit is tighter). */
        const val MAX_PACKAGE_NAME_LENGTH = 256

        /** Session names are user-facing UI strings; keep them short. */
        const val MAX_SESSION_NAME_LENGTH = 64

        /**
         * Strict Android package name: >=2 dot-separated segments, each
         * starting with a letter, then letters/digits/underscore only.
         * (Mirrors Play's conventions — a one-segment package cannot be
         * installed from Play.)
         */
        private val PACKAGE_NAME = Regex("""^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$""")
    }

    /** @throws VpnError.InvalidConfig on the first invalid field. */
    fun validate() {
        validateSessionName()
        validateMtu()
        val parsedAddresses = parseAddresses()
        val parsedRoutes = parseRoutes()
        parseDnsServers()
        validateAppPackages()
        checkDuplicates("routes", parsedRoutes)

        // Cross-field: an address may double as a route for its own /prefix
        // (e.g. address 10.0.0.2/24 + route 10.0.0.0/24 is normal), so we
        // only reject duplicates WITHIN each list, not across them.
        // (Equality is by parsed bytes, so differently-spelled literals of
        // the same address are still caught.)
        checkDuplicates("addresses", parsedAddresses)
    }

    /**
     * PURE: validated → Builder-shaped parameters. This function is the
     * unit-tested heart of `ShareNetVpnService.buildInterface`.
     *
     * @throws VpnError.InvalidConfig if [validate] fails.
     */
    fun toBuilderParams(): BuilderParams {
        validate()
        return BuilderParams(
            sessionName = sessionName,
            mtu = mtu,
            addresses = parseAddresses(),
            routes = parseRoutes(),
            dnsServers = dnsServers.mapIndexed { i, literal ->
                IpAddress.parse(literal)
                    ?: throw VpnError.InvalidConfig("dnsServers[$i]", "malformed ip literal '$literal'")
            },
            appFilter = when (appFilterMode) {
                AppFilterMode.ALLOWLIST -> AppFilter.Allowlist(appPackages)
                AppFilterMode.BLOCKLIST -> AppFilter.Blocklist(appPackages)
            },
        )
    }

    private fun validateSessionName() {
        if (sessionName.isBlank()) {
            throw VpnError.InvalidConfig("sessionName", "must not be blank")
        }
        if (sessionName.length > MAX_SESSION_NAME_LENGTH) {
            throw VpnError.InvalidConfig(
                "sessionName",
                "length ${sessionName.length} exceeds bound $MAX_SESSION_NAME_LENGTH",
            )
        }
        if (sessionName.any { it.isISOControl() }) {
            throw VpnError.InvalidConfig("sessionName", "control characters are not allowed")
        }
    }

    private fun validateMtu() {
        if (mtu !in MIN_MTU..MAX_MTU) {
            throw VpnError.InvalidConfig(
                "mtu",
                "mtu $mtu outside [$MIN_MTU, $MAX_MTU]",
            )
        }
    }

    private fun parseAddresses(): List<Cidr> {
        if (addresses.isEmpty()) {
            throw VpnError.InvalidConfig("addresses", "at least one interface address is required")
        }
        return addresses.mapIndexed { i, literal ->
            // Bare IP = host address (documented); CIDR form also accepted.
            val withPrefix = if (literal.contains('/')) literal else null
            if (withPrefix != null) {
                Cidr.parse(withPrefix)
                    ?: throw VpnError.InvalidConfig("addresses[$i]", "malformed cidr '$literal'")
            } else {
                val address = IpAddress.parse(literal)
                    ?: throw VpnError.InvalidConfig("addresses[$i]", "malformed ip literal '$literal'")
                val hostPrefix = if (address.family == IpFamily.IPV4) 32 else 128
                Cidr.of(address, hostPrefix)
            }
        }
    }

    private fun parseRoutes(): List<Cidr> {
        return routes.mapIndexed { i, literal ->
            val cidr = Cidr.parse(literal)
                ?: throw VpnError.InvalidConfig(
                    "routes[$i]",
                    "malformed cidr '$literal' (form ip/prefix is required)",
                )
            if (cidr.hostBitsSet) {
                throw VpnError.InvalidConfig(
                    "routes[$i]",
                    "host bits set below /${cidr.prefixLength} in '$literal'",
                )
            }
            cidr
        }
    }

    private fun parseDnsServers(): List<IpAddress> {
        val parsed = dnsServers.mapIndexed { i, literal ->
            IpAddress.parse(literal)
                ?: throw VpnError.InvalidConfig("dnsServers[$i]", "malformed ip literal '$literal'")
        }
        checkDuplicates("dnsServers", dnsServers)
        return parsed
    }

    private fun validateAppPackages() {
        appPackages.forEachIndexed { i, name ->
            if (name.length > MAX_PACKAGE_NAME_LENGTH) {
                throw VpnError.InvalidConfig(
                    "appPackages[$i]",
                    "package name longer than $MAX_PACKAGE_NAME_LENGTH characters",
                )
            }
            if (!PACKAGE_NAME.matches(name)) {
                throw VpnError.InvalidConfig("appPackages[$i]", "not a valid package name '$name'")
            }
        }
        checkDuplicates("appPackages", appPackages)
        if (appFilterMode == AppFilterMode.ALLOWLIST && appPackages.isEmpty()) {
            throw VpnError.InvalidConfig(
                "appPackages",
                "an ALLOWLIST with no packages routes nothing — add packages or use BLOCKLIST",
            )
        }
    }

    private fun <T> checkDuplicates(field: String, values: List<T>) {
        val seen = HashSet<T>()
        for (value in values) {
            if (!seen.add(value)) {
                throw VpnError.InvalidConfig(field, "duplicate entry '$value'")
            }
        }
    }
}
