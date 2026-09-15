plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "org.sharenet.transport.nearby"
    compileSdk = 35

    defaultConfig {
        minSdk = 26

        // NOTE: this is a library. targetSdk is chosen by the embedding app
        // (manifest-merged); we compile against the current stable SDK 35.
        // The manifest declares the full permission set for current
        // targetSdk levels (see src/main/AndroidManifest.xml).
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
    // GMS boundary). No android.jar stubs are touched: keep default values so
    // any accidental framework call fails loudly instead of silently passing.
    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

dependencies {
    // The seam: every future transport implements the contract types.
    api(project(":contract"))

    // The ONLY dependency on Google Play services. GMS types are confined to
    // GmsNearbyApi.kt (the facade boundary); nothing else may import them.
    implementation("com.google.android.gms:play-services-nearby:19.5.0")

    testImplementation(kotlin("test"))
}
