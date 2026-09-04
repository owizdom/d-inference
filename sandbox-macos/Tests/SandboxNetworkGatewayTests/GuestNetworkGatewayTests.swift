import Foundation
import XCTest

@testable import SandboxNetworkGateway

final class GuestNetworkGatewayTests: XCTestCase {
    private let guestMAC = MACAddress("0a:00:27:00:00:01")!
    private let plan = GuestNetworkPlan()
    private var counters = GatewayCounters()

    private func gateway(egress: Bool = true) -> GuestNetworkGateway {
        GuestNetworkGateway(
            plan: plan, policy: EgressPolicy(egressEnabled: egress)
        )
    }

    private func frame(_ type: EtherType, _ payload: [UInt8]) -> [UInt8] {
        EthernetFrame(
            destination: plan.gatewayMAC,
            source: guestMAC,
            rawEtherType: type.rawValue,
            payload: payload
        ).encoded()
    }

    private func udpFrame(
        to destination: IPv4Address,
        port: UInt16,
        from source: IPv4Address? = nil,
        sourcePort: UInt16 = 40000,
        payload: [UInt8] = [1, 2, 3, 4]
    ) -> [UInt8] {
        let src = source ?? plan.guestAddress
        let datagram = UDPDatagram(
            sourcePort: sourcePort, destinationPort: port, payload: payload
        )
        return frame(.ipv4, IPv4Packet(
            source: src,
            destination: destination,
            rawProtocol: IPProtocol.udp.rawValue,
            payload: datagram.encoded(source: src, destination: destination)
        ).encoded())
    }

    /// The exact frame the live run showed a booting guest send first.
    func testIPv6IsDroppedAndCounted() {
        let outcome = gateway().handle(
            frame: frame(.ipv6, [UInt8](repeating: 0, count: 40)),
            counters: &counters
        )
        guard case .drop(let reason) = outcome else {
            return XCTFail("ipv6 must not be forwarded")
        }
        XCTAssertTrue(reason.contains("ipv6"), reason)
        XCTAssertEqual(counters.droppedIPv6, 1)
    }

    func testARPForTheGatewayIsAnswered() throws {
        let request = ARPPacket(
            operation: .request,
            senderHardware: guestMAC,
            senderProtocol: plan.guestAddress,
            targetHardware: MACAddress(bytes: [0, 0, 0, 0, 0, 0])!,
            targetProtocol: plan.gatewayAddress
        )
        let outcome = gateway().handle(
            frame: frame(.arp, request.encoded()), counters: &counters
        )
        guard case .reply(let bytes) = outcome else {
            return XCTFail("an arp for the gateway must be answered")
        }
        let reply = try XCTUnwrap(EthernetFrame(decoding: bytes))
        XCTAssertEqual(reply.destination, guestMAC)
        XCTAssertEqual(reply.source, plan.gatewayMAC)
        XCTAssertEqual(counters.arpAnswered, 1)
    }

    /// DHCP is answered before the guest has an address, so it must not be
    /// subject to an egress decision — even with egress fully disabled.
    func testDHCPIsAnsweredEvenWithNoEgressPolicy() throws {
        var request = [UInt8](repeating: 0, count: DHCP.fixedBytes)
        request[0] = 1; request[1] = 1; request[2] = 6
        request[28...33] = ArraySlice(guestMAC.bytes)
        request += DHCP.magicCookie + [53, 1, 1, 255]

        let outcome = gateway(egress: false).handle(
            frame: udpFrame(
                to: IPv4Address(255, 255, 255, 255),
                port: DHCP.serverPort,
                from: IPv4Address(0, 0, 0, 0),
                sourcePort: DHCP.clientPort,
                payload: request
            ),
            counters: &counters
        )
        guard case .reply = outcome else {
            return XCTFail("dhcp must be answered before egress exists")
        }
        XCTAssertEqual(counters.dhcpAnswered, 1)
        XCTAssertEqual(counters.deniedByPolicy, 0)
    }

    /// The filter runs on the address in the packet. A guest that resolved a
    /// name to a public address and then sends to the metadata endpoint still
    /// produces a packet addressed to the metadata endpoint.
    func testUDPToADeniedDestinationIsDroppedAndCounted() {
        for text in ["169.254.169.254", "10.0.0.1", "127.0.0.1", "192.168.1.1"] {
            var local = GatewayCounters()
            let outcome = gateway().handle(
                frame: udpFrame(to: IPv4Address(text)!, port: 53),
                counters: &local
            )
            guard case .drop = outcome else {
                return XCTFail("\(text) must be denied")
            }
            XCTAssertEqual(local.deniedByPolicy, 1, text)
            XCTAssertEqual(local.udpRelayed, 0, text)
        }
    }

    /// And the negative case, so the test above is not passing because
    /// everything is dropped.
    func testUDPToAnAllowedDestinationIsRelayed() {
        let outcome = gateway().handle(
            frame: udpFrame(to: IPv4Address("1.1.1.1")!, port: 53),
            counters: &counters
        )
        guard case .relayUDP(_, let sourcePort, let destination, let port, _) =
            outcome
        else {
            return XCTFail("an allowed destination must be relayed")
        }
        XCTAssertEqual(destination, IPv4Address("1.1.1.1"))
        XCTAssertEqual(port, 53)
        XCTAssertEqual(sourcePort, 40000)
        XCTAssertEqual(counters.udpRelayed, 1)
    }

    /// The guest is told the gateway is its resolver, and the gateway's own
    /// address is inside RFC1918 — so without an explicit interception the
    /// filter would deny the guest's every lookup.
    func testDNSToTheGatewayIsForwardedUpstreamNotDenied() {
        let outcome = gateway().handle(
            frame: udpFrame(to: plan.gatewayAddress, port: 53),
            counters: &counters
        )
        guard case .relayUDP(_, _, let destination, let port, _) = outcome else {
            return XCTFail("dns to the gateway must be forwarded, not denied")
        }
        XCTAssertEqual(destination, IPv4Address(1, 1, 1, 1))
        XCTAssertEqual(port, 53)
        XCTAssertEqual(counters.deniedByPolicy, 0)
    }

    /// Interception is for DNS only. Anything else aimed at the gateway's own
    /// address is still an RFC1918 destination and stays denied.
    func testOtherTrafficToTheGatewayAddressIsStillDenied() {
        let outcome = gateway().handle(
            frame: udpFrame(to: plan.gatewayAddress, port: 8080),
            counters: &counters
        )
        guard case .drop = outcome else {
            return XCTFail("only dns is intercepted")
        }
        XCTAssertEqual(counters.deniedByPolicy, 1)
    }

    func testNothingIsRelayedBeforeAPolicyIsInstalled() {
        let outcome = GuestNetworkGateway(plan: plan, policy: .denyAll)
            .handle(
                frame: udpFrame(to: IPv4Address("1.1.1.1")!, port: 53),
                counters: &counters
            )
        guard case .drop(let reason) = outcome else {
            return XCTFail("a gateway with no policy must relay nothing")
        }
        XCTAssertTrue(reason.contains("not installed"), reason)
    }

    func testEchoToTheGatewayIsAnsweredAndElsewhereIsNot() throws {
        var echo: [UInt8] = [ICMP.echoRequest, 0, 0, 0, 0, 1, 0, 1]
        echo += [0xAB, 0xCD]
        func icmpFrame(to destination: IPv4Address) -> [UInt8] {
            frame(.ipv4, IPv4Packet(
                source: plan.guestAddress,
                destination: destination,
                rawProtocol: IPProtocol.icmp.rawValue,
                payload: echo
            ).encoded())
        }

        guard case .reply(let bytes) = gateway().handle(
            frame: icmpFrame(to: plan.gatewayAddress), counters: &counters
        ) else {
            return XCTFail("echo to the gateway should be answered")
        }
        let ethernet = try XCTUnwrap(EthernetFrame(decoding: bytes))
        let packet = try XCTUnwrap(IPv4Packet(decoding: ethernet.payload))
        XCTAssertEqual(packet.payload[0], ICMP.echoReply)
        XCTAssertEqual(counters.icmpAnswered, 1)

        // ICMP anywhere else is egress, and other types steer routing.
        guard case .drop = gateway().handle(
            frame: icmpFrame(to: IPv4Address("1.1.1.1")!), counters: &counters
        ) else {
            return XCTFail("echo past the gateway must not be answered")
        }
    }

    func testTCPIsHonestlyUnhandledForNow() {
        let outcome = gateway().handle(
            frame: frame(.ipv4, IPv4Packet(
                source: plan.guestAddress,
                destination: IPv4Address("1.1.1.1")!,
                rawProtocol: IPProtocol.tcp.rawValue,
                payload: [UInt8](repeating: 0, count: 20)
            ).encoded()),
            counters: &counters
        )
        guard case .drop(let reason) = outcome else {
            return XCTFail("tcp is not handled yet and must not be forwarded")
        }
        XCTAssertTrue(reason.contains("tcp"), reason)
    }

    func testFragmentsAndGarbageAreDropped() {
        let fragment = frame(.ipv4, IPv4Packet(
            source: plan.guestAddress,
            destination: IPv4Address("1.1.1.1")!,
            rawProtocol: IPProtocol.udp.rawValue,
            flagsAndFragmentOffset: 0x2000,
            payload: [UInt8](repeating: 0, count: 8)
        ).encoded())
        guard case .drop = gateway().handle(frame: fragment, counters: &counters)
        else { return XCTFail("fragments must not be forwarded") }

        guard case .drop = gateway().handle(frame: [1, 2, 3], counters: &counters)
        else { return XCTFail("garbage must not be forwarded") }
        XCTAssertEqual(counters.droppedMalformed, 1)
    }
}
