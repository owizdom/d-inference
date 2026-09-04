import Foundation

/// An ARP packet, restricted to IPv4-over-Ethernet.
///
/// The gateway answers requests for its own address and ignores everything
/// else. It never learns from a guest's replies: there is exactly one host on
/// this link and the gateway already knows its own address, so an ARP cache
/// fed by the guest would be a way to redirect traffic, not a convenience.
public struct ARPPacket: Equatable, Sendable {
    public static let byteCount = 28
    public enum Operation: UInt16, Sendable {
        case request = 1
        case reply = 2
    }

    public let operation: Operation
    public let senderHardware: MACAddress
    public let senderProtocol: IPv4Address
    public let targetHardware: MACAddress
    public let targetProtocol: IPv4Address

    public init(
        operation: Operation,
        senderHardware: MACAddress,
        senderProtocol: IPv4Address,
        targetHardware: MACAddress,
        targetProtocol: IPv4Address
    ) {
        self.operation = operation
        self.senderHardware = senderHardware
        self.senderProtocol = senderProtocol
        self.targetHardware = targetHardware
        self.targetProtocol = targetProtocol
    }

    public init?(decoding bytes: [UInt8]) {
        guard bytes.count >= Self.byteCount else { return nil }
        // Ethernet (1) over IPv4 (0x0800), 6-byte MACs and 4-byte addresses.
        guard bytes[0] == 0, bytes[1] == 1,
              bytes[2] == 0x08, bytes[3] == 0x00,
              bytes[4] == 6, bytes[5] == 4
        else {
            return nil
        }
        guard let operation = Operation(
            rawValue: UInt16(bytes[6]) << 8 | UInt16(bytes[7])
        ) else {
            return nil
        }
        guard let senderHardware = MACAddress(bytes: Array(bytes[8..<14])),
              let senderProtocol = IPv4Address(bytes: bytes[14..<18]),
              let targetHardware = MACAddress(bytes: Array(bytes[18..<24])),
              let targetProtocol = IPv4Address(bytes: bytes[24..<28])
        else {
            return nil
        }
        self.operation = operation
        self.senderHardware = senderHardware
        self.senderProtocol = senderProtocol
        self.targetHardware = targetHardware
        self.targetProtocol = targetProtocol
    }

    public func encoded() -> [UInt8] {
        var out: [UInt8] = [0, 1, 0x08, 0x00, 6, 4]
        out.append(UInt8(truncatingIfNeeded: operation.rawValue >> 8))
        out.append(UInt8(truncatingIfNeeded: operation.rawValue))
        out += senderHardware.bytes
        out += senderProtocol.octets
        out += targetHardware.bytes
        out += targetProtocol.octets
        return out
    }

    /// The reply to a request for `address`, or nil when the request is for
    /// something else.
    ///
    /// Answering for an address the gateway does not own would make it a proxy
    /// for hosts it has no business speaking for.
    public func reply(
        forGatewayAddress address: IPv4Address,
        gatewayMAC: MACAddress
    ) -> ARPPacket? {
        guard operation == .request, targetProtocol == address else {
            return nil
        }
        return ARPPacket(
            operation: .reply,
            senderHardware: gatewayMAC,
            senderProtocol: address,
            targetHardware: senderHardware,
            targetProtocol: senderProtocol
        )
    }
}
