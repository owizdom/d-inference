import Darwin
import Foundation

/// Forwards guest UDP to real sockets and carries the answers back.
///
/// One connected socket per flow, keyed by what the guest chose. Connected
/// rather than `sendto`/`recvfrom` because the kernel then drops anything from
/// a source the flow did not address, which is the cheapest possible defence
/// against an off-path answer being handed to the guest as a reply.
public final class UDPRelay: @unchecked Sendable {
    public struct FlowKey: Hashable, Sendable {
        public let guestPort: UInt16
        public let destination: IPv4Address
        public let destinationPort: UInt16
    }

    /// A reply to hand back to the guest.
    public struct Reply: Sendable {
        public let key: FlowKey
        public let payload: [UInt8]
    }

    private struct Flow {
        let descriptor: Int32
        var lastUsed: Date
    }

    /// Enough for a DNS answer and then some; larger datagrams are truncated
    /// by the kernel, which is what a real host would do too.
    static let maximumDatagramBytes = 4 * 1024

    /// Bounded so a guest cannot exhaust the daemon's descriptors by spraying
    /// source ports. The oldest idle flow is retired to make room.
    public let maximumFlows: Int
    public let idleTimeout: TimeInterval

    private let lock = NSLock()
    private var flows: [FlowKey: Flow] = [:]

    public init(maximumFlows: Int = 256, idleTimeout: TimeInterval = 60) {
        self.maximumFlows = maximumFlows
        self.idleTimeout = idleTimeout
    }

    deinit { closeAll() }

    public func closeAll() {
        lock.withLock {
            for flow in flows.values { close(flow.descriptor) }
            flows.removeAll()
        }
    }

    public var flowCount: Int { lock.withLock { flows.count } }

    /// Sends one datagram, opening a flow if this is the first.
    @discardableResult
    public func send(
        key: FlowKey,
        payload: [UInt8],
        now: Date = Date()
    ) -> Bool {
        lock.withLock {
            expireLocked(now: now)
            let descriptor: Int32
            if let existing = flows[key] {
                descriptor = existing.descriptor
                flows[key]?.lastUsed = now
            } else {
                guard flows.count < maximumFlows,
                      let opened = openLocked(key)
                else {
                    return false
                }
                descriptor = opened
                flows[key] = Flow(descriptor: opened, lastUsed: now)
            }
            let sent = payload.withUnsafeBytes { raw in
                Darwin.send(descriptor, raw.baseAddress, raw.count, 0)
            }
            return sent == payload.count
        }
    }

    /// Drains whatever has come back. Never blocks.
    public func poll(now: Date = Date()) -> [Reply] {
        lock.withLock {
            var replies: [Reply] = []
            for (key, flow) in flows {
                var buffer = [UInt8](
                    repeating: 0, count: Self.maximumDatagramBytes
                )
                while true {
                    let count = buffer.withUnsafeMutableBytes { raw in
                        Darwin.recv(flow.descriptor, raw.baseAddress, raw.count, 0)
                    }
                    guard count > 0 else { break }
                    replies.append(
                        Reply(key: key, payload: Array(buffer[0..<count]))
                    )
                    flows[key]?.lastUsed = now
                }
            }
            expireLocked(now: now)
            return replies
        }
    }

    private func openLocked(_ key: FlowKey) -> Int32? {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { return nil }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = key.destinationPort.bigEndian
        address.sin_addr.s_addr = key.destination.value.bigEndian
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }
        let flags = fcntl(descriptor, F_GETFL)
        guard connected == 0, flags >= 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
        else {
            close(descriptor)
            return nil
        }
        return descriptor
    }

    private func expireLocked(now: Date) {
        let stale = flows.filter {
            now.timeIntervalSince($0.value.lastUsed) > idleTimeout
        }
        for (key, flow) in stale {
            close(flow.descriptor)
            flows.removeValue(forKey: key)
        }
    }
}
