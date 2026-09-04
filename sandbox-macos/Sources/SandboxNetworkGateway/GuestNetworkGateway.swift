import Foundation

/// What the gateway decided to do with one frame. Returned rather than acted
/// on so the decision is testable without any sockets.
public enum FrameOutcome: Equatable, Sendable {
    /// Send these bytes back to the guest.
    case reply([UInt8])
    /// Forward this datagram, then send any answer back to the guest.
    case relayUDP(
        source: IPv4Address, sourcePort: UInt16,
        destination: IPv4Address, destinationPort: UInt16,
        payload: [UInt8]
    )
    case drop(reason: String)
}

/// The frame handler: everything the gateway decides, with no I/O.
///
/// Pure by construction. A packet gateway is exactly the kind of code that has
/// to be provable against crafted input, and none of these decisions need a
/// socket to make — so the socket work lives in the loop that calls this, and
/// every rule here is testable directly.
public struct GuestNetworkGateway: Sendable {
    public let plan: GuestNetworkPlan
    public let policy: EgressPolicy
    public let dnsServer: IPv4Address
    /// Where the gateway sends the lookups it intercepts.
    ///
    /// The gateway's choice, never the guest's: a resolver the guest could name
    /// would be a destination it could reach, and the point of advertising the
    /// gateway is that it cannot.
    public let upstreamDNS: IPv4Address

    static let dnsPort: UInt16 = 53

    public init(
        plan: GuestNetworkPlan = GuestNetworkPlan(),
        policy: EgressPolicy = .denyAll,
        dnsServer: IPv4Address? = nil,
        upstreamDNS: IPv4Address = IPv4Address(1, 1, 1, 1)
    ) {
        self.plan = plan
        self.policy = policy
        // The gateway answers DNS itself so the guest never learns a resolver
        // address it could reach directly.
        self.dnsServer = dnsServer ?? plan.gatewayAddress
        self.upstreamDNS = upstreamDNS
    }

    public func handle(
        frame bytes: [UInt8],
        counters: inout GatewayCounters
    ) -> FrameOutcome {
        counters.framesReceived += 1
        guard let frame = EthernetFrame(decoding: bytes) else {
            counters.droppedMalformed += 1
            return .drop(reason: "not an ethernet frame")
        }
        // A guest can spoof any source it likes; the gateway only ever answers
        // the MAC in front of it, so a spoofed source reaches nobody else.
        switch frame.etherType {
        case .arp:
            return handleARP(frame, counters: &counters)
        case .ipv4:
            return handleIPv4(frame, counters: &counters)
        case .ipv6:
            // Dropped outright rather than forwarded. A guest emits IPv6 —
            // MLD and mDNS — before it has an IPv4 address at all, and under a
            // NAT those frames reach the host's LAN.
            counters.droppedIPv6 += 1
            return .drop(reason: "ipv6 is not forwarded")
        case .none:
            counters.droppedUnsupported += 1
            return .drop(
                reason: "unsupported ethertype 0x"
                    + String(frame.rawEtherType, radix: 16)
            )
        }
    }

    private func handleARP(
        _ frame: EthernetFrame,
        counters: inout GatewayCounters
    ) -> FrameOutcome {
        guard let request = ARPPacket(decoding: frame.payload) else {
            counters.droppedMalformed += 1
            return .drop(reason: "malformed arp")
        }
        guard let reply = request.reply(
            forGatewayAddress: plan.gatewayAddress,
            gatewayMAC: plan.gatewayMAC
        ) else {
            counters.droppedUnsupported += 1
            return .drop(reason: "arp not for the gateway")
        }
        counters.arpAnswered += 1
        return .reply(
            EthernetFrame(
                destination: request.senderHardware,
                source: plan.gatewayMAC,
                rawEtherType: EtherType.arp.rawValue,
                payload: reply.encoded()
            ).encoded()
        )
    }

    private func handleIPv4(
        _ frame: EthernetFrame,
        counters: inout GatewayCounters
    ) -> FrameOutcome {
        guard let packet = IPv4Packet(decoding: frame.payload) else {
            counters.droppedMalformed += 1
            return .drop(reason: "malformed ipv4")
        }
        guard !packet.isFragment else {
            // Only the first fragment carries a transport header, so a later
            // one cannot be checked against a port-aware policy.
            counters.droppedUnsupported += 1
            return .drop(reason: "ipv4 fragments are not forwarded")
        }

        switch packet.ipProtocol {
        case .udp:
            return handleUDP(frame, packet, counters: &counters)
        case .icmp:
            return handleICMP(frame, packet, counters: &counters)
        case .tcp:
            // Arrives in the next step. Dropping is the honest answer now.
            counters.droppedUnsupported += 1
            return .drop(reason: "tcp is not handled yet")
        case .none:
            counters.droppedUnsupported += 1
            return .drop(
                reason: "unsupported ip protocol \(packet.rawProtocol)"
            )
        }
    }

    private func handleUDP(
        _ frame: EthernetFrame,
        _ packet: IPv4Packet,
        counters: inout GatewayCounters
    ) -> FrameOutcome {
        guard let datagram = UDPDatagram(decoding: packet.payload) else {
            counters.droppedMalformed += 1
            return .drop(reason: "malformed udp")
        }

        // DHCP is answered by the gateway itself. It arrives before the guest
        // has an address, so it cannot be subject to an egress decision.
        if datagram.destinationPort == DHCP.serverPort {
            guard let message = DHCP.parse(datagram.payload),
                  let reply = DHCP.reply(
                      to: message, plan: plan, dnsServer: dnsServer
                  )
            else {
                counters.droppedMalformed += 1
                return .drop(reason: "malformed or unanswerable dhcp")
            }
            counters.dhcpAnswered += 1
            return .reply(
                encodeToGuest(
                    destinationMAC: message.clientMAC,
                    source: plan.gatewayAddress,
                    // Answer to broadcast: the guest has no address configured
                    // yet, so a unicast reply may be dropped by its own stack.
                    destination: IPv4Address(255, 255, 255, 255),
                    udp: UDPDatagram(
                        sourcePort: DHCP.serverPort,
                        destinationPort: DHCP.clientPort,
                        payload: reply
                    )
                )
            )
        }

        // DNS addressed to the gateway is answered by forwarding upstream, not
        // by egress. The guest is told the gateway is its resolver precisely so
        // it never learns a resolver address it could reach directly — but the
        // gateway's own address is inside RFC1918, so without this the policy
        // would deny the guest's every lookup.
        if packet.destination == plan.gatewayAddress,
           datagram.destinationPort == Self.dnsPort {
            counters.udpRelayed += 1
            return .relayUDP(
                source: packet.source,
                sourcePort: datagram.sourcePort,
                destination: upstreamDNS,
                destinationPort: Self.dnsPort,
                payload: datagram.payload
            )
        }

        switch policy.decide(destination: packet.destination) {
        case .deny(let reason):
            counters.deniedByPolicy += 1
            return .drop(reason: reason)
        case .allow:
            counters.udpRelayed += 1
            return .relayUDP(
                source: packet.source,
                sourcePort: datagram.sourcePort,
                destination: packet.destination,
                destinationPort: datagram.destinationPort,
                payload: datagram.payload
            )
        }
    }

    private func handleICMP(
        _ frame: EthernetFrame,
        _ packet: IPv4Packet,
        counters: inout GatewayCounters
    ) -> FrameOutcome {
        // Only echo addressed to the gateway itself. Echo to anywhere else is
        // egress and belongs to the policy; other ICMP types are a way to steer
        // a host's routing rather than a diagnostic.
        guard packet.destination == plan.gatewayAddress,
              let reply = ICMP.echoReply(for: packet.payload)
        else {
            counters.droppedUnsupported += 1
            return .drop(reason: "only icmp echo to the gateway is answered")
        }
        counters.icmpAnswered += 1
        return .reply(
            EthernetFrame(
                destination: frame.source,
                source: plan.gatewayMAC,
                rawEtherType: EtherType.ipv4.rawValue,
                payload: IPv4Packet(
                    source: plan.gatewayAddress,
                    destination: packet.source,
                    rawProtocol: IPProtocol.icmp.rawValue,
                    payload: reply
                ).encoded()
            ).encoded()
        )
    }

    /// Wraps a UDP datagram in IPv4 and Ethernet, addressed to the guest.
    public func encodeToGuest(
        destinationMAC: MACAddress,
        source: IPv4Address,
        destination: IPv4Address,
        udp: UDPDatagram
    ) -> [UInt8] {
        EthernetFrame(
            destination: destinationMAC,
            source: plan.gatewayMAC,
            rawEtherType: EtherType.ipv4.rawValue,
            payload: IPv4Packet(
                source: source,
                destination: destination,
                rawProtocol: IPProtocol.udp.rawValue,
                payload: udp.encoded(source: source, destination: destination)
            ).encoded()
        ).encoded()
    }
}
