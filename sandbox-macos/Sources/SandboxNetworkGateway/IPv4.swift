import Foundation

/// An IPv4 address, kept as four bytes because that is how it appears on the
/// wire and how the filter compares it.
public struct IPv4Address: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let bytes: (UInt8, UInt8, UInt8, UInt8)

    public init(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        bytes = (a, b, c, d)
    }

    public init?(bytes: ArraySlice<UInt8>) {
        guard bytes.count == 4 else { return nil }
        let b = Array(bytes)
        self.bytes = (b[0], b[1], b[2], b[3])
    }

    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for part in parts {
            guard let value = UInt8(part) else { return nil }
            out.append(value)
        }
        bytes = (out[0], out[1], out[2], out[3])
    }

    public var octets: [UInt8] { [bytes.0, bytes.1, bytes.2, bytes.3] }

    public var description: String {
        "\(bytes.0).\(bytes.1).\(bytes.2).\(bytes.3)"
    }

    public var value: UInt32 {
        UInt32(bytes.0) << 24 | UInt32(bytes.1) << 16
            | UInt32(bytes.2) << 8 | UInt32(bytes.3)
    }

    public static func == (lhs: IPv4Address, rhs: IPv4Address) -> Bool {
        lhs.value == rhs.value
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(value)
    }
}

/// IP protocol numbers this gateway handles.
public enum IPProtocol: UInt8, Sendable {
    case icmp = 1
    case tcp = 6
    case udp = 17
}

/// A parsed IPv4 packet.
///
/// Options are preserved but never interpreted. A guest can set any it likes,
/// and source routing in particular is a way to ask a forwarder to reach
/// somewhere the destination field does not name — so a packet carrying options
/// is rejected outright rather than forwarded on the strength of its
/// destination alone.
public struct IPv4Packet: Equatable, Sendable {
    public static let minimumHeaderBytes = 20

    public let source: IPv4Address
    public let destination: IPv4Address
    public let rawProtocol: UInt8
    public let timeToLive: UInt8
    public let identification: UInt16
    public let flagsAndFragmentOffset: UInt16
    public let payload: [UInt8]

    public var ipProtocol: IPProtocol? { IPProtocol(rawValue: rawProtocol) }

    /// Whether this is a fragment — either not the last one, or offset into a
    /// larger datagram.
    ///
    /// Fragments are refused. Reassembling them is how a filter gets bypassed:
    /// the transport header a policy wants to read lives only in the first
    /// fragment, so a later one carries a destination with no port to check.
    public var isFragment: Bool {
        let moreFragments = (flagsAndFragmentOffset & 0x2000) != 0
        let offset = flagsAndFragmentOffset & 0x1FFF
        return moreFragments || offset != 0
    }

    public init(
        source: IPv4Address,
        destination: IPv4Address,
        rawProtocol: UInt8,
        timeToLive: UInt8 = 64,
        identification: UInt16 = 0,
        flagsAndFragmentOffset: UInt16 = 0x4000,
        payload: [UInt8]
    ) {
        self.source = source
        self.destination = destination
        self.rawProtocol = rawProtocol
        self.timeToLive = timeToLive
        self.identification = identification
        self.flagsAndFragmentOffset = flagsAndFragmentOffset
        self.payload = payload
    }

    public init?(decoding bytes: [UInt8]) {
        guard bytes.count >= Self.minimumHeaderBytes else { return nil }
        guard bytes[0] >> 4 == 4 else { return nil }
        let headerWords = Int(bytes[0] & 0x0F)
        // Anything past the minimum is options, which this gateway refuses.
        guard headerWords == 5 else { return nil }
        let totalLength = Int(bytes[2]) << 8 | Int(bytes[3])
        // A total length longer than the frame means a truncated packet; one
        // shorter means trailing padding, which Ethernet adds to short frames.
        guard totalLength >= Self.minimumHeaderBytes,
              totalLength <= bytes.count
        else {
            return nil
        }
        guard Self.checksum(Array(bytes[0..<Self.minimumHeaderBytes])) == 0
        else {
            return nil
        }
        guard let source = IPv4Address(bytes: bytes[12..<16]),
              let destination = IPv4Address(bytes: bytes[16..<20])
        else {
            return nil
        }
        self.source = source
        self.destination = destination
        identification = UInt16(bytes[4]) << 8 | UInt16(bytes[5])
        flagsAndFragmentOffset = UInt16(bytes[6]) << 8 | UInt16(bytes[7])
        timeToLive = bytes[8]
        rawProtocol = bytes[9]
        payload = Array(bytes[Self.minimumHeaderBytes..<totalLength])
    }

    public func encoded() -> [UInt8] {
        var header = [UInt8](repeating: 0, count: Self.minimumHeaderBytes)
        header[0] = 0x45
        let total = Self.minimumHeaderBytes + payload.count
        header[2] = UInt8(truncatingIfNeeded: total >> 8)
        header[3] = UInt8(truncatingIfNeeded: total)
        header[4] = UInt8(truncatingIfNeeded: identification >> 8)
        header[5] = UInt8(truncatingIfNeeded: identification)
        header[6] = UInt8(truncatingIfNeeded: flagsAndFragmentOffset >> 8)
        header[7] = UInt8(truncatingIfNeeded: flagsAndFragmentOffset)
        header[8] = timeToLive
        header[9] = rawProtocol
        header[12...15] = ArraySlice(source.octets)
        header[16...19] = ArraySlice(destination.octets)
        let sum = Self.checksum(header)
        header[10] = UInt8(truncatingIfNeeded: sum >> 8)
        header[11] = UInt8(truncatingIfNeeded: sum)
        return header + payload
    }

    /// The one's-complement sum used by IPv4, ICMP, and the TCP/UDP pseudo
    /// header. Returns 0 over a header that already carries a valid checksum,
    /// which is how decoding validates one.
    public static func checksum(_ bytes: [UInt8], seed: UInt32 = 0) -> UInt16 {
        var total = seed
        var index = 0
        while index + 1 < bytes.count {
            total += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count {
            total += UInt32(bytes[index]) << 8
        }
        while total >> 16 != 0 {
            total = (total & 0xFFFF) + (total >> 16)
        }
        return UInt16(truncatingIfNeeded: ~total)
    }
}
