import Darwin
import Foundation

/// Drives one guest's network: frames in, decisions out, replies back.
///
/// The decisions live in `GuestNetworkGateway`, which touches no sockets. This
/// is only the I/O around them, so everything worth arguing about is testable
/// without a VM.
public final class GatewayLoop: @unchecked Sendable {
    private let channel: GuestFrameChannel
    private let gateway: GuestNetworkGateway
    private let relay: UDPRelay
    private let lock = NSLock()
    private var countersStorage = GatewayCounters()
    /// Learned from the frames the guest sends rather than configured.
    ///
    /// The gateway has no independent source for it — Lume assigns the MAC —
    /// and a wrong value would send every reply to a host that is not there.
    /// Nothing can be owed to the guest before it has spoken, so learning it is
    /// always in time.
    private var learnedGuestMAC: MACAddress?

    /// How long to wait before polling again when nothing happened. Short
    /// enough that a DNS answer is not visibly delayed, long enough that an
    /// idle guest costs nothing.
    public static let idlePollInterval: Duration = .milliseconds(5)

    public var counters: GatewayCounters { lock.withLock { countersStorage } }

    public init(
        descriptor: Int32,
        gateway: GuestNetworkGateway,
        relay: UDPRelay = UDPRelay()
    ) {
        channel = GuestFrameChannel(descriptor: descriptor)
        self.gateway = gateway
        self.relay = relay
    }

    /// Runs until the guest's channel closes, which is what makes a tenant's
    /// network die with its VM without anything having to notice the exit.
    public func run() async {
        defer { relay.closeAll() }
        while !Task.isCancelled {
            var didWork = false
            do {
                didWork = try pumpGuest() || didWork
            } catch {
                return
            }
            didWork = pumpReplies() || didWork
            if !didWork {
                try? await Task.sleep(for: Self.idlePollInterval)
            }
        }
    }

    /// One pass over whatever the guest has sent. Returns whether anything
    /// was there.
    func pumpGuest() throws -> Bool {
        var handled = false
        // Bounded so a guest flooding frames cannot starve the reply path.
        for _ in 0..<64 {
            guard let bytes = try channel.receive() else { break }
            handled = true
            if let frame = EthernetFrame(decoding: bytes), !frame.source.isGroup {
                lock.withLock { learnedGuestMAC = frame.source }
            }
            let outcome = lock.withLock {
                gateway.handle(frame: bytes, counters: &countersStorage)
            }
            switch outcome {
            case .reply(let frame):
                try? channel.send(frame)
                lock.withLock { countersStorage.framesSent += 1 }
            case .relayUDP(_, let sourcePort, let destination, let port, let payload):
                relay.send(
                    key: UDPRelay.FlowKey(
                        guestPort: sourcePort,
                        destination: destination,
                        destinationPort: port
                    ),
                    payload: payload
                )
            case .drop:
                break
            }
        }
        return handled
    }

    /// Carries whatever came back to the guest.
    func pumpReplies() -> Bool {
        let replies = relay.poll()
        guard let guestMAC = lock.withLock({ learnedGuestMAC }) else {
            // Nothing can be owed to a guest that has not spoken.
            return !replies.isEmpty
        }
        for reply in replies {
            // Answers come from the address the guest addressed, so a lookup
            // sent to the gateway is answered by the gateway rather than by an
            // upstream address the guest never named.
            let source = reply.key.destinationPort == 53
                && reply.key.destination == gateway.upstreamDNS
                ? gateway.plan.gatewayAddress
                : reply.key.destination
            let frame = gateway.encodeToGuest(
                destinationMAC: guestMAC,
                source: source,
                destination: gateway.plan.guestAddress,
                udp: UDPDatagram(
                    sourcePort: reply.key.destinationPort,
                    destinationPort: reply.key.guestPort,
                    payload: reply.payload
                )
            )
            try? channel.send(frame)
            lock.withLock { countersStorage.framesSent += 1 }
        }
        return !replies.isEmpty
    }
}
