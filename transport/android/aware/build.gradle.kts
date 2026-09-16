plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "org.sharenet.transport.aware"
    compileSdk = 35

    defaultConfig {
        minSdk = 26

        // NOTE: this is a library. targetSdk is chosen by the embedding app
        // (manifest-merged); we compile against the current stable SDK 35.
        // Wi-Fi Aware itself is a platform capability (API 26+ discovery,
        // API 33+ modern specifier datapaths — see AndroidAwareApi for the
        // honest API-level caveats). The manifest declares the full aware
        // permission set for current targetSdk levels.
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

    // Unit tests are pure JVM (adapter logic against the scripted fake at the
    // android.net.wifi.aware boundary). No android.jar stubs are touched:
    // keep default values so any accidental framework call fails loudly
    // instead of silently passing (the R2-001 module protocol).
    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

dependencies {
    // The seam: the aware adapter speaks ONLY contract types (lock L009).
    api(project(":contract"))

    // ZERO third-party dependencies: Wi-Fi Aware (IEEE 802.11mc NAN) is an
    // Android platform capability, not a Google Play services add-on. All
    // android.net.wifi.aware.* types are confined to AndroidAwareApi.kt.
    testImplementation(kotlin("test"))
}
