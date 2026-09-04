import Darwin
import Foundation
import XCTest

@testable import SandboxNetworkGateway

final class UDPRelayTests: XCTestCase {
    /// A real UDP echo server on loopback, so the relay is exercised against
    /// actual sockets rather than a stand-in.
    private func echoServer() throws -> (port: UInt16, stop: () -> Void) {
        let listener = socket(AF_INET, SOCK_DGRAM, 0)
        guard listener >= 0 else { throw XCTSkip("no socket") }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian   // 127.0.0.1
        address.sin_port = 0
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { close(listener); throw XCTSkip("cannot bind") }

        // A blocking recvfrom on a background thread can outlive the test if
        // the wake-up is missed, and a thread parked forever stalls the whole
        // suite rather than failing one case. A receive timeout makes that
        // impossible instead of unlikely.
        var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
        _ = setsockopt(
            listener, SOL_SOCKET, SO_RCVTIMEO, &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )

        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listener, $0, &length)
            }
        }
        let port = UInt16(bigEndian: actual.sin_port)

        let running = NSLock()
        var stopped = false
        let thread = Thread {
            var buffer = [UInt8](repeating: 0, count: 2048)
            while true {
                running.lock()
                let done = stopped
                running.unlock()
                if done { break }
                var from = sockaddr_storage()
                var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let count = buffer.withUnsafeMutableBytes { raw in
                    withUnsafeMutablePointer(to: &from) { pointer in
                        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            recvfrom(
                                listener, raw.baseAddress, raw.count, 0,
                                $0, &fromLength
                            )
                        }
                    }
                }
                guard count > 0 else { continue }
                _ = buffer.withUnsafeBytes { raw in
                    withUnsafePointer(to: &from) { pointer in
                        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            sendto(
                                listener, raw.baseAddress, count, 0,
                                $0, fromLength
                            )
                        }
                    }
                }
            }
            close(listener)
        }
        thread.start()
        return (port, {
            running.lock(); stopped = true; running.unlock()
            // Still nudged, so teardown is prompt rather than up to a timeout.
            let poke = socket(AF_INET, SOCK_DGRAM, 0)
            var to = sockaddr_in()
            to.sin_family = sa_family_t(AF_INET)
            to.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian
            to.sin_port = port.bigEndian
            var byte: UInt8 = 0
            _ = withUnsafePointer(to: &to) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(poke, &byte, 1, 0, $0,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            close(poke)
        })
    }

    func testADatagramGoesOutAndTheAnswerComesBack() throws {
        let server = try echoServer()
        defer { server.stop() }
        let relay = UDPRelay()
        defer { relay.closeAll() }

        let key = UDPRelay.FlowKey(
            guestPort: 40000,
            destination: IPv4Address(127, 0, 0, 1),
            destinationPort: server.port
        )
        XCTAssertTrue(relay.send(key: key, payload: Array("hello".utf8)))

        var replies: [UDPRelay.Reply] = []
        let deadline = Date().addingTimeInterval(3)
        while replies.isEmpty, Date() < deadline {
            replies = relay.poll()
            if replies.isEmpty { usleep(20_000) }
        }
        XCTAssertEqual(replies.count, 1)
        XCTAssertEqual(replies.first.map { Array($0.payload) }, Array("hello".utf8))
        XCTAssertEqual(replies.first?.key, key)
    }

    /// A guest spraying source ports must not exhaust the daemon's
    /// descriptors, so flows are bounded and refused past the cap.
    func testFlowsAreBoundedSoAGuestCannotExhaustDescriptors() {
        let relay = UDPRelay(maximumFlows: 3)
        defer { relay.closeAll() }
        for port in UInt16(1)...UInt16(3) {
            XCTAssertTrue(relay.send(
                key: .init(
                    guestPort: port,
                    destination: IPv4Address(127, 0, 0, 1),
                    destinationPort: 9
                ),
                payload: [0]
            ))
        }
        XCTAssertEqual(relay.flowCount, 3)
        XCTAssertFalse(
            relay.send(
                key: .init(
                    guestPort: 4,
                    destination: IPv4Address(127, 0, 0, 1),
                    destinationPort: 9
                ),
                payload: [0]
            ),
            "past the cap a new flow is refused, not opened"
        )
    }

    func testIdleFlowsAreRetired() {
        let relay = UDPRelay(maximumFlows: 4, idleTimeout: 1)
        defer { relay.closeAll() }
        let start = Date()
        relay.send(
            key: .init(
                guestPort: 1,
                destination: IPv4Address(127, 0, 0, 1),
                destinationPort: 9
            ),
            payload: [0],
            now: start
        )
        XCTAssertEqual(relay.flowCount, 1)
        _ = relay.poll(now: start.addingTimeInterval(5))
        XCTAssertEqual(relay.flowCount, 0, "an idle flow is closed")
    }
}
