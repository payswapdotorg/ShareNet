import XCTest
@testable import ShareNetParticipant

/// The transport session state machine (`ConnectionTracker`) — the Swift
/// mirror of the Android contract tracker's suite, including the seeded
/// fuzz-lite convergence run.
final class ConnectionTrackerTests: XCTestCase {

    private func anyEndpoint(_ tag: String) -> EndpointID {
        EndpointID("endpoint-\(tag)")
    }

    // MARK: Activity ladder

    func testActivityLadderLegalAndIllegalTransitions() throws {
        let tracker = ConnectionTracker()
        XCTAssertTrue(tracker.isIdle)
        XCTAssertFalse(tracker.isActive)

        try tracker.startAdvertising()
        XCTAssertTrue(tracker.isAdvertising)
        XCTAssertThrowsError(try tracker.startAdvertising()) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
        XCTAssertFalse(tracker.isIdle)

        try tracker.startDiscovery()
        XCTAssertTrue(tracker.isActive)

        try tracker.stopDiscovery()
        XCTAssertThrowsError(try tracker.stopDiscovery()) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }

        try tracker.stopAdvertising()
        XCTAssertThrowsError(try tracker.stopAdvertising()) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
        XCTAssertTrue(tracker.isIdle)
    }

    func testRapidStartStopCyclesConverge() {
        // The lenient stopAll is the convergence point after ANY failure.
        let tracker = ConnectionTracker()
        for _ in 0..<50 {
            try? tracker.startAdvertising()
            try? tracker.startDiscovery()
            tracker.stopAll()
            XCTAssertTrue(tracker.isIdle)
            XCTAssertTrue(tracker.activeEndpointIds().isEmpty)
        }
    }

    // MARK: Endpoint ladder

    func testInboundHappyPathLadder() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("inbound-1")

        try tracker.onConnectionRequested(endpoint)
        XCTAssertTrue(tracker.isEndpointPending(endpoint))

        try tracker.acceptConnection(endpoint)
        XCTAssertTrue(tracker.isEndpointPending(endpoint))
        XCTAssertFalse(tracker.isEndpointConnected(endpoint))

        try tracker.onConnectionAccepted(endpoint)
        XCTAssertTrue(tracker.isEndpointConnected(endpoint))
        XCTAssertNoThrow(try tracker.assertCanSend(endpoint))

        try tracker.onDisconnected(endpoint)
        XCTAssertFalse(tracker.isEndpointConnected(endpoint))
        XCTAssertEqual(tracker.activeEndpointIds(), [])
    }

    func testOutboundFlowRequestedDirectToConnected() throws {
        // The R3-001 outbound flow: request, platform confirm without a
        // local accept.
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("outbound-1")
        try tracker.onConnectionRequested(endpoint)
        try tracker.onConnectionAccepted(endpoint)
        XCTAssertTrue(tracker.isEndpointConnected(endpoint))
    }

    func testAcceptWithoutRequestThrows() {
        let tracker = ConnectionTracker()
        XCTAssertThrowsError(try tracker.acceptConnection(anyEndpoint("unknown"))) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testDuplicateRequestThrows() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("dup")
        try tracker.onConnectionRequested(endpoint)
        XCTAssertThrowsError(try tracker.onConnectionRequested(endpoint)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testDoubleAcceptThrows() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("double-accept")
        try tracker.onConnectionRequested(endpoint)
        try tracker.acceptConnection(endpoint)
        XCTAssertThrowsError(try tracker.acceptConnection(endpoint)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testRejectAfterAcceptThrows() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("late-reject")
        try tracker.onConnectionRequested(endpoint)
        try tracker.acceptConnection(endpoint)
        XCTAssertThrowsError(try tracker.rejectConnection(endpoint)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testRejectBeforeAcceptRemovesEndpoint() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("early-reject")
        try tracker.onConnectionRequested(endpoint)
        try tracker.rejectConnection(endpoint)
        XCTAssertFalse(tracker.isEndpointPending(endpoint))
    }

    func testUnknownDisconnectThrows() {
        let tracker = ConnectionTracker()
        XCTAssertThrowsError(try tracker.onDisconnected(anyEndpoint("ghost"))) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testDuplicateConfirmationThrows() throws {
        let tracker = ConnectionTracker()
        let endpoint = anyEndpoint("dup-confirm")
        try tracker.onConnectionRequested(endpoint)
        try tracker.onConnectionAccepted(endpoint)
        XCTAssertThrowsError(try tracker.onConnectionAccepted(endpoint)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testAssertCanSendDistinguishesStates() throws {
        let tracker = ConnectionTracker()
        let requested = anyEndpoint("requested")
        let accepted = anyEndpoint("accepted")
        let connected = anyEndpoint("connected")

        try tracker.onConnectionRequested(requested)
        try tracker.onConnectionRequested(accepted)
        try tracker.acceptConnection(accepted)
        try tracker.onConnectionRequested(connected)
        try tracker.onConnectionAccepted(connected)

        XCTAssertThrowsError(try tracker.assertCanSend(requested))
        XCTAssertThrowsError(try tracker.assertCanSend(accepted))
        XCTAssertNoThrow(try tracker.assertCanSend(connected))
        XCTAssertThrowsError(try tracker.assertCanSend(anyEndpoint("never-seen")))
    }

    func testEndpointOrderIsInsertionOrder() throws {
        let tracker = ConnectionTracker()
        let first = anyEndpoint("a")
        let second = anyEndpoint("b")
        let third = anyEndpoint("c")
        try tracker.onConnectionRequested(first)
        try tracker.onConnectionRequested(second)
        try tracker.onConnectionRequested(third)
        XCTAssertEqual(tracker.activeEndpointIds(), [first, second, third])
        try tracker.onDisconnected(second)
        XCTAssertEqual(tracker.activeEndpointIds(), [first, third])
    }

    // MARK: Fuzz-lite (deterministic, seeded)

    func testFuzzLiteRandomOperationSequencesConvergeToLegalStates() throws {
        var random = SeededRandom(seed: 0xC0FFEE)
        let tracker = ConnectionTracker()
        let ids = (0..<8).map { anyEndpoint("fuzz-\($0)") }

        for _ in 0..<2_000 {
            let id = ids[random.nextIndex(upperBound: ids.count)]
            switch random.nextIndex(upperBound: 12) {
            case 0: try? tracker.startAdvertising()
            case 1: try? tracker.stopAdvertising()
            case 2: try? tracker.startDiscovery()
            case 3: try? tracker.stopDiscovery()
            case 4: try? tracker.onConnectionRequested(id)
            case 5: try? tracker.acceptConnection(id)
            case 6: try? tracker.rejectConnection(id)
            case 7: try? tracker.onConnectionAccepted(id)
            case 8: try? tracker.onConnectionRejected(id)
            case 9: try? tracker.onDisconnected(id)
            case 10: tracker.abandonConnection(id)
            default: try? tracker.assertCanSend(id)
            }

            // Invariants after every operation.
            let snapshot = tracker.snapshot()
            XCTAssertEqual(snapshot.advertising, tracker.isAdvertising)
            XCTAssertEqual(snapshot.discovering, tracker.isDiscovering)
            for (id, connected) in snapshot.endpoints {
                XCTAssertEqual(connected, tracker.isEndpointConnected(id))
                XCTAssertTrue(tracker.activeEndpointIds().contains(id))
            }
            for id in tracker.activeEndpointIds() {
                XCTAssertTrue(snapshot.endpoints[id] != nil)
            }
        }

        tracker.stopAll()
        XCTAssertTrue(tracker.isIdle)
        XCTAssertTrue(tracker.activeEndpointIds().isEmpty)
    }
}
