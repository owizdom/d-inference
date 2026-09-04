import Foundation

/// An IPv4 range, as a base address and prefix length.
public struct IPv4Prefix: Equatable, Sendable, CustomStringConvertible {
    public let base: IPv4Address
    public let prefixLength: UInt8

    public init?(_ base: IPv4Address, _ prefixLength: UInt8) {
        guard prefixLength <= 32 else { return nil }
        self.base = base
        self.prefixLength = prefixLength
    }

    public init?(_ text: String) {
        let parts = text.split(separator: "/")
        guard parts.count == 2,
              let base = IPv4Address(String(parts[0])),
              let length = UInt8(parts[1]),
              length <= 32
        else {
            return nil
        }
        self.base = base
        prefixLength = length
    }

    public var description: String { "\(base)/\(prefixLength)" }

    public func contains(_ address: IPv4Address) -> Bool {
        guard prefixLength > 0 else { return true }
        let shift = 32 - UInt32(prefixLength)
        let mask: UInt32 = shift == 32 ? 0 : ~UInt32(0) << shift
        return (address.value & mask) == (base.value & mask)
    }
}

/// What a tenant may send a packet to.
///
/// 🛑 This is evaluated **per packet, against the destination in the packet**,
/// never against a hostname resolved earlier. That is the whole reason DNS
/// rebinding is a non-issue here: a name that resolved to a public address a
/// moment ago and to `169.254.169.254` now still produces a packet addressed to
/// `169.254.169.254`, and this sees that address.
public struct EgressPolicy: Sendable {
    /// Ranges a tenant must never reach, whatever else is configured.
    ///
    /// Denied unconditionally rather than by omission from an allowlist: these
    /// are the addresses that lead back to the provider, its neighbours, and
    /// cloud credential endpoints, so they must not become reachable by anyone
    /// widening a policy later.
    public static let alwaysDenied: [IPv4Prefix] = [
        IPv4Prefix("0.0.0.0/8")!,          // "this network"
        IPv4Prefix("10.0.0.0/8")!,         // RFC1918
        IPv4Prefix("127.0.0.0/8")!,        // the host's own loopback
        IPv4Prefix("169.254.0.0/16")!,     // link-local, incl. 169.254.169.254
        IPv4Prefix("172.16.0.0/12")!,      // RFC1918
        IPv4Prefix("192.168.0.0/16")!,     // RFC1918, incl. the VM subnets
        IPv4Prefix("100.64.0.0/10")!,      // carrier-grade NAT
        IPv4Prefix("192.0.0.0/24")!,       // IETF protocol assignments
        IPv4Prefix("198.18.0.0/15")!,      // benchmarking
        IPv4Prefix("224.0.0.0/4")!,        // multicast
        IPv4Prefix("240.0.0.0/4")!,        // reserved, incl. 255.255.255.255
    ]

    public enum Decision: Equatable, Sendable {
        case allow
        case deny(reason: String)
    }

    /// Whether any egress at all is permitted yet.
    ///
    /// Default-deny is the starting state, not a configuration choice: a
    /// sandbox admitted before its policy arrives must reach nothing rather
    /// than everything.
    public let egressEnabled: Bool

    /// Additional ranges this deployment denies, beyond the unconditional set —
    /// a provider's own LAN, for instance.
    public let additionalDenied: [IPv4Prefix]

    public init(
        egressEnabled: Bool = false,
        additionalDenied: [IPv4Prefix] = []
    ) {
        self.egressEnabled = egressEnabled
        self.additionalDenied = additionalDenied
    }

    /// A policy that denies everything. What a gateway starts with.
    public static let denyAll = EgressPolicy(egressEnabled: false)

    public func decide(destination: IPv4Address) -> Decision {
        guard egressEnabled else {
            return .deny(reason: "egress policy not installed")
        }
        for prefix in Self.alwaysDenied where prefix.contains(destination) {
            return .deny(reason: "destination in reserved range \(prefix)")
        }
        for prefix in additionalDenied where prefix.contains(destination) {
            return .deny(reason: "destination in denied range \(prefix)")
        }
        return .allow
    }
}
