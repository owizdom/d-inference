import Foundation
import XCTest

@testable import SandboxNetworkGateway

final class IPv4Tests: XCTestCase {
    /// A real UDP packet a guest would send: DHCP DISCOVER, 0.0.0.0 to the
    /// broadcast address.
    private func discoverHeader(
        totalLength: Int = 28,
        headerWords: UInt8 = 5,
        flagsAndFragment: UInt16 = 0,
        proto: UInt8 = 17
    ) -> [UInt8] {
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x40 | headerWords
        header[2] = UInt8(truncatingIfNeeded: totalLength >> 8)
        header[3] = UInt8(truncatingIfNeeded: totalLength)
        header[6] = UInt8(truncatingIfNeeded: flagsAndFragment >> 8)
        header[7] = UInt8(truncatingIfNeeded: flagsAndFragment)
        header[8] = 64
        header[9] = proto
        header[12...15] = ArraySlice([0, 0, 0, 0])
        header[16...19] = ArraySlice([255, 255, 255, 255])
        let sum = IPv4Packet.checksum(header)
        header[10] = UInt8(truncatingIfNeeded: sum >> 8)
        header[11] = UInt8(truncatingIfNeeded: sum)
        return header
    }

    func testDecodesAndReEncodesWithoutDrift() throws {
        let bytes = discoverHeader() + [UInt8](repeating: 0xAB, count: 8)
        let packet = try XCTUnwrap(IPv4Packet(decoding: bytes))

        XCTAssertEqual(packet.source, IPv4Address("0.0.0.0"))
        XCTAssertEqual(packet.destination, IPv4Address("255.255.255.255"))
        XCTAssertEqual(packet.ipProtocol, .udp)
        XCTAssertEqual(packet.payload.count, 8)
        // Re-encoding recomputes the checksum, and the result decodes again.
        XCTAssertNotNil(IPv4Packet(decoding: packet.encoded()))
    }

    /// A wrong checksum means a corrupt packet. Forwarding one would relay
    /// whatever the corruption produced, including its destination.
    func testABadChecksumIsRejected() {
        var bytes = discoverHeader() + [UInt8](repeating: 0, count: 8)
        bytes[10] ^= 0xFF
        XCTAssertNil(IPv4Packet(decoding: bytes))
    }

    /// Options are how a guest asks a forwarder to reach somewhere its
    /// destination field does not name. Refused rather than ignored.
    func testHeaderOptionsAreRefused() {
        let bytes = discoverHeader(totalLength: 24, headerWords: 6)
            + [UInt8](repeating: 0, count: 4)
        XCTAssertNil(
            IPv4Packet(decoding: bytes),
            "a packet with options must not decode"
        )
    }

    /// Fragments are how a filter gets bypassed: only the first carries the
    /// transport header a policy wants to read.
    func testFragmentsAreIdentifiable() throws {
        let more = try XCTUnwrap(
            IPv4Packet(decoding: discoverHeader(flagsAndFragment: 0x2000)
                + [UInt8](repeating: 0, count: 8))
        )
        XCTAssertTrue(more.isFragment, "more-fragments set")

        let offset = try XCTUnwrap(
            IPv4Packet(decoding: discoverHeader(flagsAndFragment: 0x0001)
                + [UInt8](repeating: 0, count: 8))
        )
        XCTAssertTrue(offset.isFragment, "non-zero offset")

        let whole = try XCTUnwrap(
            IPv4Packet(decoding: discoverHeader(flagsAndFragment: 0x4000)
                + [UInt8](repeating: 0, count: 8))
        )
        XCTAssertFalse(whole.isFragment, "don't-fragment is not a fragment")
    }

    /// Ethernet pads short frames, so the frame is often longer than the
    /// packet. Trusting the frame length instead of the header's would relay
    /// padding as payload.
    func testTrailingEthernetPaddingIsNotPayload() throws {
        let bytes = discoverHeader(totalLength: 28)
            + [UInt8](repeating: 0xAB, count: 8)
            + [UInt8](repeating: 0x00, count: 18)   // pad to 60 bytes
        let packet = try XCTUnwrap(IPv4Packet(decoding: bytes))
        XCTAssertEqual(packet.payload, [UInt8](repeating: 0xAB, count: 8))
    }

    /// A length claiming more than arrived is a truncated packet.
    func testATruncatedPacketIsRejected() {
        let bytes = discoverHeader(totalLength: 200)
            + [UInt8](repeating: 0, count: 8)
        XCTAssertNil(IPv4Packet(decoding: bytes))
    }

    func testRejectsShortAndNonIPv4Input() {
        XCTAssertNil(IPv4Packet(decoding: []))
        XCTAssertNil(IPv4Packet(decoding: [UInt8](repeating: 0, count: 19)))
        var sixish = discoverHeader()
        sixish[0] = 0x65                              // version 6
        XCTAssertNil(IPv4Packet(decoding: sixish))
    }

    func testChecksumIsZeroOverAValidHeader() {
        // The property decoding relies on: a header carrying a correct
        // checksum sums to zero.
        XCTAssertEqual(IPv4Packet.checksum(discoverHeader()), 0)
    }
}
