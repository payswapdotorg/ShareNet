package org.sharenet.transport.vpn

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * VpnConfig strict-validation table tests (R4-004): every invalid shape
 * is rejected with a TYPED [VpnError.InvalidConfig] naming the field —
 * no silent defaults, no silent repairs.
 */
class VpnConfigTest {

    private fun minimalConfig(
        sessionName: String = "sharenet-bridge",
        addresses: List<String> = listOf("10.111.111.2/32"),
        routes: List<String> = listOf("0.0.0.0/0"),
        dnsServers: List<String> = emptyList(),
        appPackages: List<String> = emptyList(),
        appFilterMode: AppFilterMode = AppFilterMode.BLOCKLIST,
        mtu: Int = VpnConfig.DEFAULT_MTU,
    ) = VpnConfig(sessionName, addresses, routes, dnsServers, appPackages, appFilterMode, mtu)

    private fun invalidField(block: () -> Unit): VpnError.InvalidConfig {
        val error = assertFailsWith<VpnError.InvalidConfig> { block() }
        return error
    }

    // ---------- happy paths ----------

    @Test
    fun minimal_config_validates_and_maps_to_builder_params() {
        val params = minimalConfig().toBuilderParams()
        assertEquals("sharenet-bridge", params.sessionName)
        assertEquals(VpnConfig.DEFAULT_MTU, params.mtu)
        assertEquals(listOf("10.111.111.2/32"), params.addresses.map { it.toString() })
        assertEquals(listOf("0.0.0.0/0"), params.routes.map { it.toString() })
        assertEquals(emptyList(), params.dnsServers)
        assertEquals(AppFilter.Blocklist(emptyList()), params.appFilter)
    }

    @Test
    fun default_mtu_is_1280_and_bounds_are_inclusive() {
        assertEquals(1280, VpnConfig.DEFAULT_MTU)
        assertEquals(1280, minimalConfig(mtu = 1280).toBuilderParams().mtu)
        assertEquals(68, minimalConfig(mtu = 68).toBuilderParams().mtu)
        assertEquals(65535, minimalConfig(mtu = 65535).toBuilderParams().mtu)
    }

    @Test
    fun full_config_roundtrips_every_field() {
        val config = VpnConfig(
            sessionName = "gateway-42",
            addresses = listOf("10.111.111.2/32", "fd00::2/128"),
            routes = listOf("0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/32"),
            dnsServers = listOf("10.111.111.1", "fd00::1"),
            appPackages = listOf("org.sharenet.app", "org.sharenet.other"),
            appFilterMode = AppFilterMode.ALLOWLIST,
            mtu = 1400,
        )
        val params = config.toBuilderParams()
        assertEquals(4, params.routes.size)
        assertEquals(2, params.dnsServers.size)
        assertEquals(AppFilter.Allowlist(listOf("org.sharenet.app", "org.sharenet.other")), params.appFilter)
        assertEquals(1400, params.mtu)
        assertEquals(IpFamily.IPV6, params.dnsServers[1].family)
    }

    // ---------- sessionName ----------

    @Test
    fun blank_session_name_rejected() {
        for (name in listOf("", "   ", "\t\n")) {
            assertEquals("sessionName", invalidField { minimalConfig(sessionName = name).validate() }.field)
        }
    }

    @Test
    fun oversized_session_name_rejected() {
        val name = "x".repeat(VpnConfig.MAX_SESSION_NAME_LENGTH + 1)
        assertEquals("sessionName", invalidField { minimalConfig(sessionName = name).validate() }.field)
    }

    @Test
    fun control_characters_in_session_name_rejected() {
        assertEquals("sessionName", invalidField { minimalConfig(sessionName = "bad\u0007name").validate() }.field)
    }

    // ---------- mtu ----------

    @Test
    fun mtu_out_of_bounds_rejected_both_sides() {
        assertEquals("mtu", invalidField { minimalConfig(mtu = 67).validate() }.field)
        assertEquals("mtu", invalidField { minimalConfig(mtu = 65_536).validate() }.field)
        assertEquals("mtu", invalidField { minimalConfig(mtu = 0).validate() }.field)
        assertEquals("mtu", invalidField { minimalConfig(mtu = -1).validate() }.field)
    }

    // ---------- addresses ----------

    @Test
    fun empty_address_list_rejected() {
        assertEquals("addresses", invalidField { minimalConfig(addresses = emptyList()).validate() }.field)
    }

    @Test
    fun bare_address_ip_becomes_host_prefix() {
        val params = VpnConfig(
            sessionName = "s",
            addresses = listOf("10.111.111.2", "fd00::2"),
        ).toBuilderParams()
        assertEquals("10.111.111.2/32", params.addresses[0].toString())
        assertEquals("fd00::2/128", params.addresses[1].toString())
    }

    @Test
    fun malformed_addresses_rejected() {
        for (bad in listOf(
            "300.1.2.3",
            "10.0.0",
            "10.0.0.0.1",
            "010.0.0.1", // leading zero: strict rejection
            "10.0.0.1/33",
            "10.0.0.1/-1",
            "10.0.0.1/",
            "10.0.0.1/8/9",
            "10.0.0.1/08",
            "fd00::2/129",
            "",
        )) {
            val error = invalidField { VpnConfig("s", listOf(bad)).validate() }
            assertEquals("addresses[0]", error.field, "expected addresses[0] for '$bad'")
            assertTrue(error.reason.contains("malformed"))
        }
    }

    @Test
    fun duplicate_addresses_rejected_across_spellings() {
        // Same address, two spellings, one host prefix: still a duplicate.
        assertEquals("addresses", invalidField {
            VpnConfig("s", listOf("10.0.0.1", "10.0.0.1/32")).validate()
        }.field)
    }

    // ---------- routes ----------

    @Test
    fun valid_routes_accepted_including_catch_alls() {
        val params = minimalConfig(
            routes = listOf("0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32", "fd00::/8"),
        ).toBuilderParams()
        assertEquals(6, params.routes.size)
    }

    @Test
    fun routes_require_explicit_prefix() {
        assertEquals(
            "routes[0]",
            invalidField { minimalConfig(routes = listOf("10.0.0.0")).validate() }.field,
        )
    }

    @Test
    fun routes_with_host_bits_rejected() {
        for (dirty in listOf("10.0.0.1/8", "192.168.1.1/24", "2001:db8::1/32", "fe80::1/64", "::1/64")) {
            val error = invalidField { minimalConfig(routes = listOf(dirty)).validate() }
            assertEquals("routes[0]", error.field, "expected routes[0] for '$dirty'")
            assertContains(error.reason, "host bits")
        }
    }

    @Test
    fun host_route_prefixes_are_legal() {
        // /32 and /128 routes have nothing below the prefix: clean.
        minimalConfig(routes = listOf("10.0.0.1/32", "::1/128")).validate()
    }

    @Test
    fun route_prefix_out_of_family_bounds_rejected() {
        assertEquals(
            "routes[0]",
            invalidField { minimalConfig(routes = listOf("10.0.0.0/33")).validate() }.field,
        )
        assertEquals(
            "routes[1]",
            invalidField { minimalConfig(routes = listOf("0.0.0.0/0", "::/129")).validate() }.field,
        )
    }

    @Test
    fun duplicate_routes_rejected() {
        assertEquals(
            "routes",
            invalidField { minimalConfig(routes = listOf("10.0.0.0/8", "10.0.0.0/8")).validate() }.field,
        )
    }

    // ---------- dns ----------

    @Test
    fun dns_servers_accept_plain_v4_and_v6_literals() {
        val params = minimalConfig(dnsServers = listOf("10.111.111.1", "fd00::1", "8.8.8.8")).toBuilderParams()
        assertEquals(3, params.dnsServers.size)
        assertEquals(IpFamily.IPV4, params.dnsServers[0].family)
        assertEquals(IpFamily.IPV6, params.dnsServers[1].family)
    }

    @Test
    fun dns_servers_reject_prefix_forms_and_garbage() {
        for (bad in listOf("8.8.8.8/32", "fd00::1/128", "not-an-ip", "", "8.8.8.8.8", "fe80:::1")) {
            assertEquals(
                "dnsServers[0]",
                invalidField { minimalConfig(dnsServers = listOf(bad)).validate() }.field,
                "expected dnsServers[0] for '$bad'",
            )
        }
    }

    @Test
    fun duplicate_dns_servers_rejected() {
        assertEquals(
            "dnsServers",
            invalidField { minimalConfig(dnsServers = listOf("8.8.8.8", "8.8.8.8")).validate() }.field,
        )
    }

    // ---------- app packages ----------

    @Test
    fun valid_package_names_accepted() {
        minimalConfig(
            appPackages = listOf("org.sharenet.app", "com.example.gps_logger_2"),
            appFilterMode = AppFilterMode.ALLOWLIST,
        ).validate()
    }

    @Test
    fun malformed_package_names_rejected() {
        for (bad in listOf(
            "",
            "com", // single segment: not installable from Play
            "1com.example", // segment must start with a letter
            "com..example",
            "com.example.app!",
            "com.exa mple",
            "com.example.app.", // trailing dot = empty segment
            "com.example.app..x",
            "com.example/_app",
        )) {
            assertEquals(
                "appPackages[0]",
                invalidField {
                    minimalConfig(appPackages = listOf(bad), appFilterMode = AppFilterMode.ALLOWLIST).validate()
                }.field,
                "expected appPackages[0] for '$bad'",
            )
        }
    }

    @Test
    fun java_package_letter_case_is_accepted() {
        // Java package rules (letters/digits/underscore, letter-starting
        // segments) govern the regex; Android tolerates case, so do we —
        // strictness is about STRUCTURE, and Play's lowercase preference
        // is the store's business, not the Builder's.
        minimalConfig(
            appPackages = listOf("Com.Example.App"),
            appFilterMode = AppFilterMode.ALLOWLIST,
        ).validate()
    }

    @Test
    fun duplicate_package_names_rejected() {
        assertEquals(
            "appPackages",
            invalidField {
                minimalConfig(
                    appPackages = listOf("org.sharenet.app", "org.sharenet.app"),
                    appFilterMode = AppFilterMode.ALLOWLIST,
                ).validate()
            }.field,
        )
    }

    @Test
    fun empty_allowlist_rejected_but_empty_blocklist_is_all_apps() {
        assertEquals("appPackages", invalidField {
            minimalConfig(appPackages = emptyList(), appFilterMode = AppFilterMode.ALLOWLIST).validate()
        }.field)
        // BLOCKLIST + empty = route all apps: the default shape.
        val params = minimalConfig(appPackages = emptyList(), appFilterMode = AppFilterMode.BLOCKLIST)
            .toBuilderParams()
        assertIs<AppFilter.Blocklist>(params.appFilter)
        assertTrue(params.appFilter.packages.isEmpty())
    }

    @Test
    fun filter_modes_map_to_the_right_app_filter_type() {
        val allow = minimalConfig(
            appPackages = listOf("org.sharenet.app"),
            appFilterMode = AppFilterMode.ALLOWLIST,
        ).toBuilderParams().appFilter
        assertIs<AppFilter.Allowlist>(allow)
        assertEquals(listOf("org.sharenet.app"), allow.packages)

        val block = minimalConfig(
            appPackages = listOf("org.sharenet.app"),
            appFilterMode = AppFilterMode.BLOCKLIST,
        ).toBuilderParams().appFilter
        assertIs<AppFilter.Blocklist>(block)
        assertEquals(listOf("org.sharenet.app"), block.packages)
    }

    @Test
    fun field_paths_index_the_offending_entry() {
        assertEquals(
            "routes[2]",
            invalidField {
                minimalConfig(routes = listOf("0.0.0.0/0", "10.0.0.0/8", "300.0.0.0/8")).validate()
            }.field,
        )
    }

    // ---------- strict IP literal forms (via dnsServers) ----------

    @Test
    fun ipv6_literal_forms() {
        for (good in listOf("::", "::1", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0db8:0001", "1:2:3:4:5:6:7:8", "fe80::")) {
            minimalConfig(dnsServers = listOf(good)).validate()
        }
        for (bad in listOf(
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            ":::",
            "12345::",
            "1:2:3:4:5:6:7",
            "::ffff:192.168.0.1", // embedded v4: rejected by strict policy
            ":1",
            "1:",
        )) {
            assertEquals(
                "dnsServers[0]",
                invalidField { minimalConfig(dnsServers = listOf(bad)).validate() }.field,
                "expected rejection for '$bad'",
            )
        }
    }
}
