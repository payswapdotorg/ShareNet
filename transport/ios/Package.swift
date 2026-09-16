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
// HONEST SCOPE: this package was authored in a Linux sandbox with NO Swift
// toolchain — it has NOT been compiled or executed here. Building/testing
// requires macOS 13+ with Xcode 15+ (or a Swift 5.9+ toolchain). See
// README.md ("Sandbox honesty") for the recorded gaps.
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
