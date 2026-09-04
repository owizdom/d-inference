import Foundation
import XCTest

@testable import SandboxNetworkGateway

final class ARPTests: XCTestCase {
    private let guestMAC = MACAddress("0a:00:27:00:00:01")!
    private let plan = GuestNetworkPlan()

    private func request(for target: IPv4Address) -> ARPPacket {
        ARPPacket(
            operation: .request,
            senderHardware: guestMAC,
            senderProtocol: plan.guestAddress,
            targetHardware: MACAddress(bytes: [0, 0, 0, 0, 0, 0])!,
            targetProtocol: target
        )
    }

    func testAnswersOnlyForItsOwnAddress() throws {
        let mine = request(for: plan.gatewayAddress)
        let reply = try XCTUnwrap(
            mine.reply(forGatewayAddress: plan.gatewayAddress,
                       gatewayMAC: plan.gatewayMAC)
        )
        XCTAssertEqual(reply.operation, .reply)
        XCTAssertEqual(reply.senderHardware, plan.gatewayMAC)
        XCTAssertEqual(reply.senderProtocol, plan.gatewayAddress)
        XCTAssertEqual(reply.targetHardware, guestMAC)

        // Answering for an address it does not own would make the gateway a
        // proxy for hosts it has no business speaking for.
        XCTAssertNil(
            request(for: IPv4Address("8.8.8.8")!)
                .reply(forGatewayAddress: plan.gatewayAddress,
                       gatewayMAC: plan.gatewayMAC)
        )
    }

    func testRepliesAreNotAnsweredAgain() {
        let reply = ARPPacket(
            operation: .reply,
            senderHardware: guestMAC,
            senderProtocol: plan.gatewayAddress,
            targetHardware: plan.gatewayMAC,
            targetProtocol: plan.gatewayAddress
        )
        XCTAssertNil(
            reply.reply(forGatewayAddress: plan.gatewayAddress,
                        gatewayMAC: plan.gatewayMAC),
            "a guest's reply must not produce traffic"
        )
    }

    func testRoundTripsAndRejectsOtherProtocols() throws {
        let packet = request(for: plan.gatewayAddress)
        let decoded = try XCTUnwrap(ARPPacket(decoding: packet.encoded()))
        XCTAssertEqual(decoded, packet)

        var wrong = packet.encoded()
        wrong[3] = 0x06                       // not IPv4
        XCTAssertNil(ARPPacket(decoding: wrong))
        XCTAssertNil(ARPPacket(decoding: Array(packet.encoded().prefix(20))))
    }
}

final class DHCPTests: XCTestCase {
    private let guestMAC = MACAddress("0a:00:27:00:00:01")!
    private let plan = GuestNetworkPlan()
    private let dns = IPv4Address(192, 168, 127, 1)

    private func clientMessage(
        type: DHCP.MessageType,
        requested: IPv4Address? = nil
    ) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: DHCP.fixedBytes)
        out[0] = 1; out[1] = 1; out[2] = 6
        out[4] = 0xDE; out[5] = 0xAD; out[6] = 0xBE; out[7] = 0xEF
        out[28...33] = ArraySlice(guestMAC.bytes)
        out += DHCP.magicCookie
        out += [53, 1, type.rawValue]
        if let requested {
            out += [50, 4] + requested.octets
        }
        out += [255]
        return out
    }

    private func options(in reply: [UInt8]) -> [UInt8: [UInt8]] {
        var found: [UInt8: [UInt8]] = [:]
        var i = DHCP.fixedBytes + DHCP.magicCookie.count
        while i < reply.count, reply[i] != 255 {
            if reply[i] == 0 { i += 1; continue }
            let length = Int(reply[i + 1])
            found[reply[i]] = Array(reply[(i + 2)..<(i + 2 + length)])
            i += 2 + length
        }
        return found
    }

    func testDiscoverIsOfferedTheOneAddressOnTheLink() throws {
        let parsed = try XCTUnwrap(
            DHCP.parse(clientMessage(type: .discover))
        )
        XCTAssertEqual(parsed.type, .discover)
        XCTAssertEqual(parsed.clientMAC, guestMAC)
        XCTAssertEqual(parsed.transactionID, 0xDEADBEEF)

        let reply = try XCTUnwrap(
            DHCP.reply(to: parsed, plan: plan, dnsServer: dns)
        )
        let found = options(in: reply)
        XCTAssertEqual(found[53], [DHCP.MessageType.offer.rawValue])
        XCTAssertEqual(Array(reply[16..<20]), plan.guestAddress.octets)
        XCTAssertEqual(found[1], plan.netmask.octets)
        XCTAssertEqual(found[3], plan.gatewayAddress.octets)
        XCTAssertEqual(found[6], dns.octets)
        // The transaction id must come back or the client ignores the reply.
        XCTAssertEqual(Array(reply[4..<8]), [0xDE, 0xAD, 0xBE, 0xEF])
    }

    /// A guest that remembers a lease from a previous network must give it up
    /// at once rather than retrying until it times out.
    func testARequestForTheWrongAddressIsRefusedNotIgnored() throws {
        let parsed = try XCTUnwrap(
            DHCP.parse(clientMessage(
                type: .request, requested: IPv4Address("192.168.64.22")!
            ))
        )
        let reply = try XCTUnwrap(
            DHCP.reply(to: parsed, plan: plan, dnsServer: dns)
        )
        XCTAssertEqual(options(in: reply)[53], [DHCP.MessageType.nak.rawValue])
        // A NAK carries no address.
        XCTAssertEqual(Array(reply[16..<20]), [0, 0, 0, 0])
    }

    func testARequestForTheRightAddressIsAcknowledged() throws {
        let parsed = try XCTUnwrap(
            DHCP.parse(clientMessage(
                type: .request, requested: plan.guestAddress
            ))
        )
        let reply = try XCTUnwrap(
            DHCP.reply(to: parsed, plan: plan, dnsServer: dns)
        )
        XCTAssertEqual(options(in: reply)[53], [DHCP.MessageType.ack.rawValue])
        XCTAssertEqual(Array(reply[16..<20]), plan.guestAddress.octets)
    }

    /// A guest must not be handed extra routes: there is nowhere else on this
    /// link, and a classless-static-route option is a way to ask for one.
    func testNoExtraRoutesAreOffered() throws {
        let parsed = try XCTUnwrap(DHCP.parse(clientMessage(type: .discover)))
        let reply = try XCTUnwrap(
            DHCP.reply(to: parsed, plan: plan, dnsServer: dns)
        )
        let found = options(in: reply)
        XCTAssertNil(found[121], "no classless static routes")
        XCTAssertNil(found[33], "no static routes")
    }

    func testReleaseAndDeclineAreNotAnswered() throws {
        for type in [DHCP.MessageType.release, .decline] {
            let parsed = try XCTUnwrap(DHCP.parse(clientMessage(type: type)))
            XCTAssertNil(DHCP.reply(to: parsed, plan: plan, dnsServer: dns))
        }
    }

    func testMalformedInputIsRejected() {
        XCTAssertNil(DHCP.parse([]))
        XCTAssertNil(DHCP.parse([UInt8](repeating: 0, count: 240)))
        var noCookie = clientMessage(type: .discover)
        noCookie[DHCP.fixedBytes] = 0
        XCTAssertNil(DHCP.parse(noCookie))
        // A truncated option length must not read past the buffer.
        var truncated = [UInt8](repeating: 0, count: DHCP.fixedBytes)
        truncated[0] = 1; truncated[1] = 1; truncated[2] = 6
        truncated += DHCP.magicCookie + [53, 40]
        XCTAssertNil(DHCP.parse(truncated))
    }
}
