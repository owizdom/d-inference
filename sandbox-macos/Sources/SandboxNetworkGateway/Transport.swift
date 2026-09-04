import Foundation

/// A UDP datagram.
public struct UDPDatagram: Equatable, Sendable {
    public static let headerBytes = 8

    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let payload: [UInt8]

    public init(sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.payload = payload
    }

    public init?(decoding bytes: [UInt8]) {
        guard bytes.count >= Self.headerBytes else { return nil }
        let length = Int(bytes[4]) << 8 | Int(bytes[5])
        // The length field covers the header too, and must not claim more
        // than arrived; a longer one would read payload that is not there.
        guard length >= Self.headerBytes, length <= bytes.count else {
            return nil
        }
        sourcePort = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        destinationPort = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        payload = Array(bytes[Self.headerBytes..<length])
    }

    /// Encodes with a checksum over the IPv4 pseudo header.
    ///
    /// A zero checksum is legal in IPv4 UDP and means "not computed", but a
    /// real one is cheap and some guests discard datagrams without it.
    public func encoded(source: IPv4Address, destination: IPv4Address) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Self.headerBytes)
        out[0] = UInt8(truncatingIfNeeded: sourcePort >> 8)
        out[1] = UInt8(truncatingIfNeeded: sourcePort)
        out[2] = UInt8(truncatingIfNeeded: destinationPort >> 8)
        out[3] = UInt8(truncatingIfNeeded: destinationPort)
        let length = Self.headerBytes + payload.count
        out[4] = UInt8(truncatingIfNeeded: length >> 8)
        out[5] = UInt8(truncatingIfNeeded: length)
        out += payload

        var pseudo = source.octets + destination.octets
        pseudo += [0, IPProtocol.udp.rawValue]
        pseudo += [UInt8(truncatingIfNeeded: length >> 8),
                   UInt8(truncatingIfNeeded: length)]
        var sum = IPv4Packet.checksum(pseudo + out)
        // 0 means "no checksum" on the wire, so a computed 0 is sent as 0xFFFF.
        if sum == 0 { sum = 0xFFFF }
        out[6] = UInt8(truncatingIfNeeded: sum >> 8)
        out[7] = UInt8(truncatingIfNeeded: sum)
        return out
    }
}

/// The subset of ICMP the gateway answers: echo, so a guest can prove its link
/// works without needing anything past the gateway.
public enum ICMP {
    public static let echoRequest: UInt8 = 8
    public static let echoReply: UInt8 = 0

    /// Turns an echo request into its reply, or returns nil for anything else.
    ///
    /// Only echo is handled. Forwarding arbitrary ICMP would relay redirects
    /// and unreachables a guest invented, which are a way to steer a host's
    /// routing rather than a diagnostic.
    public static func echoReply(for payload: [UInt8]) -> [UInt8]? {
        guard payload.count >= 8, payload[0] == echoRequest else { return nil }
        var out = payload
        out[0] = echoReply
        out[2] = 0
        out[3] = 0
        let sum = IPv4Packet.checksum(out)
        out[2] = UInt8(truncatingIfNeeded: sum >> 8)
        out[3] = UInt8(truncatingIfNeeded: sum)
        return out
    }
}
