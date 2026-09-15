package org.sharenet.transport.vpn

/**
 * Strict IP literal / CIDR types (R4-004) — pure Kotlin, ZERO platform
 * dependencies (same law as the :contract module: no `android.*`, and
 * deliberately no `java.net.InetAddress`, whose parsing accepts forms we
 * must reject and may attempt resolution for non-literals).
 *
 * Strictness policy (documented, unit-tested):
 *  * IPv4: exactly four decimal octets 0..255, no leading zeros (kills the
 *    octal ambiguity "010.0.0.1"), no signs, no whitespace.
 *  * IPv6: `::`-compressed or full 8-group hex (1..4 hex digits per
 *    group), at most ONE `::`, no embedded IPv4 tail (the platform accepts
 *    `::ffff:1.2.3.4`; we reject it — callers who mean it can spell the
 *    equivalent pure-hex form).
 */
enum class IpFamily { IPV4, IPV6 }

/** A validated IP literal. [bytes] is 4 (IPv4) or 16 (IPv6) bytes long. */
class IpAddress private constructor(
    val family: IpFamily,
    val bytes: ByteArray,
    /** Canonical text form (input may differ in zero-padding). */
    val text: String,
) {
    override fun equals(other: Any?): Boolean =
        other is IpAddress && other.family == family && other.bytes.contentEquals(bytes)

    override fun hashCode(): Int = 31 * family.hashCode() + bytes.contentHashCode()

    override fun toString(): String = text

    companion object {
        /**
         * Strict-parse an IP literal. Returns null on ANY deviation — this
         * is the "reject malformed" path of [VpnConfig] validation.
         */
        fun parse(literal: String): IpAddress? {
            if (literal.isEmpty()) return null
            return if (literal.contains(':')) parseIpv6(literal) else parseIpv4(literal)
        }

        private fun parseIpv4(literal: String): IpAddress? {
            val parts = literal.split('.')
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for (i in parts.indices) {
                val part = parts[i]
                if (part.isEmpty() || part.length > 3) return null
                if (part.length > 1 && part[0] == '0') return null // no leading zeros
                var value = 0
                for (c in part) {
                    if (c !in '0'..'9') return null
                    value = value * 10 + (c - '0')
                    if (value > 255) return null
                }
                bytes[i] = value.toByte()
            }
            return IpAddress(IpFamily.IPV4, bytes, literal)
        }

        private fun parseIpv6(literal: String): IpAddress? {
            val compression = literal.indexOf("::")
            if (compression != literal.lastIndexOf("::")) return null // more than one "::"
            val groups: List<String> = if (compression >= 0) {
                if (literal == "::") return fullZeros()
                val left = literal.substring(0, compression)
                val right = literal.substring(compression + 2)
                // A single leading/trailing ':' outside the compression is malformed.
                if (left.startsWith(":") || right.endsWith(":")) return null
                if (left.isEmpty() && right.isEmpty()) return null
                val leftGroups = if (left.isEmpty()) emptyList() else left.split(':')
                val rightGroups = if (right.isEmpty()) emptyList() else right.split(':')
                if (leftGroups.size + rightGroups.size >= 8) return null // "::" must elide >= 1 group
                val filler = List(8 - leftGroups.size - rightGroups.size) { "0" }
                leftGroups + filler + rightGroups
            } else {
                val all = literal.split(':')
                if (all.size != 8) return null
                all
            }
            val bytes = ByteArray(16)
            for (i in 0 until 8) {
                val group = groups[i]
                if (group.isEmpty() || group.length > 4) return null
                var value = 0
                for (c in group) {
                    val digit = when (c) {
                        in '0'..'9' -> c - '0'
                        in 'a'..'f' -> c - 'a' + 10
                        in 'A'..'F' -> c - 'A' + 10
                        else -> return null
                    }
                    value = value * 16 + digit
                }
                bytes[i * 2] = (value shr 8).toByte()
                bytes[i * 2 + 1] = (value and 0xFF).toByte()
            }
            return IpAddress(IpFamily.IPV6, bytes, literal)
        }

        private fun fullZeros() = IpAddress(IpFamily.IPV6, ByteArray(16), "::")
    }
}

/** An IP prefix (address + prefix length), family-checked. */
class Cidr private constructor(
    val address: IpAddress,
    val prefixLength: Int,
) {
    /**
     * True when bits below the prefix are set. Legal for interface
     * ADDRESSES (a host address), rejected for ROUTES (network prefixes
     * must be clean — a dirty route is a config typo).
     */
    val hostBitsSet: Boolean
        get() {
            val maxPrefix = if (address.family == IpFamily.IPV4) 32 else 128
            for (bit in prefixLength until maxPrefix) {
                val byteIndex = bit / 8
                val bitMask = 1 shl (7 - (bit % 8))
                if (address.bytes[byteIndex].toInt() and bitMask != 0) return true
            }
            return false
        }

    override fun equals(other: Any?): Boolean =
        other is Cidr && other.address == address && other.prefixLength == prefixLength

    override fun hashCode(): Int = 31 * address.hashCode() + prefixLength

    override fun toString(): String = "$address/$prefixLength"

    companion object {
        /**
         * Strict-parse `ip/prefix` (prefix REQUIRED). Returns null when the
         * literal, the prefix, or the family/prefix combination is invalid.
         */
        fun parse(literal: String): Cidr? {
            val slash = literal.indexOf('/')
            if (slash < 0 || slash != literal.lastIndexOf('/')) return null
            val address = IpAddress.parse(literal.substring(0, slash)) ?: return null
            val prefixText = literal.substring(slash + 1)
            if (prefixText.isEmpty() || prefixText.length > 3) return null
            if (prefixText.length > 1 && prefixText[0] == '0') return null // no leading zeros
            var prefix = 0
            for (c in prefixText) {
                if (c !in '0'..'9') return null
                prefix = prefix * 10 + (c - '0')
            }
            val maxPrefix = if (address.family == IpFamily.IPV4) 32 else 128
            if (prefix > maxPrefix) return null
            return Cidr(address, prefix)
        }

        /** Build from already-validated parts. */
        internal fun of(address: IpAddress, prefixLength: Int): Cidr {
            val maxPrefix = if (address.family == IpFamily.IPV4) 32 else 128
            require(prefixLength in 0..maxPrefix) { "prefix $prefixLength invalid for ${address.family}" }
            return Cidr(address, prefixLength)
        }
    }
}
