// ShareNet Android transport (R2-001) — root build file.
//
// Module layout (see transport/android/README.md):
//   :contract — pure Kotlin/JVM transport seam, ZERO Android/GMS dependencies.
//   :nearby   — com.android.library wrapping Google Nearby Connections behind
//               the NearbyApi facade; GMS types live ONLY in GmsNearbyApi.kt.

plugins {
    id("com.android.library") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.3.21" apply false
    id("org.jetbrains.kotlin.jvm") version "2.3.21" apply false
}
