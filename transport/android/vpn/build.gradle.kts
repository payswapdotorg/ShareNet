// ShareNet Android VPN data plane (R4-004).
//
// com.android.library mirroring :nearby. All logic that can run on a JVM
// (config validation, IP packet filter, packet loop, seams) is pure
// Kotlin in src/main with ZERO android.* imports; the Android boundary
// is confined to ShareNetVpnService.kt and FdPacketIo.kt and is verified
// only by the AAR build + on-device work (R10-002). NO NDK in this
// wave — the TunnelBackhaul JNI implementation to transport/quic is the
// documented future seam.

plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "org.sharenet.transport.vpn"
    compileSdk = 35

    defaultConfig {
        minSdk = 26

        // NOTE: this is a library. targetSdk is chosen by the embedding
        // app (manifest-merged); we compile against the current stable
        // SDK 35.
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    // Unit tests are pure JVM (config/filter/loop logic over the pipe-backed
    // PacketIO fake and the echo backhaul). No android.jar stubs are touched:
    // keep default values so any accidental framework call fails loudly
    // instead of silently passing.
    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

dependencies {
    // Deliberately EMPTY production dependencies: this module speaks raw
    // IP packets, not TransportFrames, so it needs nothing from :contract
    // and no platform libraries. The join point where packets cross into
    // tunnel frames is TunnelBackhaul (JNI implementation: R10-002).
    testImplementation(kotlin("test"))
}
