// swift-tools-version: 5.9
// R9-001: iOS Network.framework participant (ShareNet platform adapter layer).
//
// Library product: ShareNetParticipant — peer discovery over Bonjour/mDNS
// (NWBrowser/NWListener), the R3-001 authenticated-link handshake seam carried
// over NWConnection, and the 4-byte big-endian length-prefixed frame I/O
// convention used across the ShareNet transport adapters.
//
// Platform floor: iOS 15 (the first ShareNet Phase-2 platform; see
// spec/architecture.md §16). macOS 13 is declared so `swift test` can run the
// pure-logic XCTest suite on a Mac (Network.framework exists on both).
//
// HONEST SCOPE (updated 2026-09-16, closure verification): the pure-Foundation
// layers (Contract/, Link/, ParticipantConfiguration) now COMPILE and the full
// pure-logic XCTest suite (32 functions) EXECUTES GREEN on Linux with
// Swift 6.1.2 (see README.md "Sandbox honesty" for the evidence record and
// the exact repro). The Network.framework adapter layer (Participant/
// NW* files) is guarded with `#if canImport(Network)` — it compiles only on
// Apple platforms (identical code when present) and its execution, plus any
// macOS/iOS compile of it, remains the operator step: macOS 13+ / Xcode 15+.
// The "ios" verification level of R9-001 stays OPEN, now narrowed to the
// Apple-only adapter layer over an executed logic core.
import PackageDescription

let package = Package(
    name: "ShareNetParticipant",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ShareNetParticipant",
            targets: ["ShareNetParticipant"]
        ),
    ],
    targets: [
        .target(
            name: "ShareNetParticipant",
            path: "Sources/ShareNetParticipant"
        ),
        .testTarget(
            name: "ShareNetParticipantTests",
            dependencies: ["ShareNetParticipant"],
            path: "Tests/ShareNetParticipantTests"
        ),
    ]
)
