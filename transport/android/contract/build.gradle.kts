plugins {
    kotlin("jvm")
}

kotlin {
    compilerOptions {
        // Kept at 17 so the Android module (minSdk 26 + D8) consumes it without
        // extra toolchain friction.
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    // Intentionally EMPTY: the contract module is the seam every future
    // transport implements and MUST stay free of Android and Google Play
    // services dependencies (architecture lock L009).
    testImplementation(kotlin("test"))
}
