import Foundation

/// The addressing a gateway hands one guest.
///
/// A /30 on a subnet Apple's NAT does not use: the link has exactly two hosts,
/// the guest and the gateway, so there is nothing else on it to reach even
/// before the filter runs.
public struct GuestNetworkPlan: Sendable {
    public let gatewayAddress: IPv4Address
    public let guestAddress: IPv4Address
    public let netmask: IPv4Address
    public let gatewayMAC: MACAddress
    public let leaseSeconds: UInt32

    public static let defaultGatewayAddress = IPv4Address(192, 168, 127, 1)
    public static let defaultGuestAddress = IPv4Address(192, 168, 127, 2)
    /// /30 — network, gateway, guest, broadcast, and nothing else.
    public static let defaultNetmask = IPv4Address(255, 255, 255, 252)
    /// Locally administered (the 0x02 bit) so it cannot collide with a real
    /// vendor address.
    public static let defaultGatewayMAC =
        MACAddress(bytes: [0x02, 0x44, 0x42, 0x00, 0x00, 0x01])!

    public init(
        gatewayAddress: IPv4Address = GuestNetworkPlan.defaultGatewayAddress,
        guestAddress: IPv4Address = GuestNetworkPlan.defaultGuestAddress,
        netmask: IPv4Address = GuestNetworkPlan.defaultNetmask,
        gatewayMAC: MACAddress = GuestNetworkPlan.defaultGatewayMAC,
        leaseSeconds: UInt32 = 3600
    ) {
        self.gatewayAddress = gatewayAddress
        self.guestAddress = guestAddress
        self.netmask = netmask
        self.gatewayMAC = gatewayMAC
        self.leaseSeconds = leaseSeconds
    }
}

/// The DHCP exchange, reduced to what one guest on a two-host link needs.
///
/// There is no lease database and no address pool. The link has one guest and
/// its address is decided before it asks, so DISCOVER and REQUEST are answered
/// with the same address every time and a lost reply costs a retry rather than
/// a different address.
public enum DHCP {
    public static let clientPort: UInt16 = 68
    public static let serverPort: UInt16 = 67
    static let magicCookie: [UInt8] = [0x63, 0x82, 0x53, 0x63]
    /// A BOOTP message is 236 bytes before options.
    static let fixedBytes = 236

    public enum MessageType: UInt8, Sendable {
        case discover = 1
        case offer = 2
        case request = 3
        case decline = 4
        case ack = 5
        case nak = 6
        case release = 7
        case inform = 8
    }

    public struct Message: Equatable, Sendable {
        public let type: MessageType
        public let transactionID: UInt32
        public let clientMAC: MACAddress
        /// The address a REQUEST is asking to confirm, when it carries one.
        public let requestedAddress: IPv4Address?
    }

    /// Parses a client message out of a UDP payload.
    public static func parse(_ bytes: [UInt8]) -> Message? {
        guard bytes.count >= fixedBytes + magicCookie.count else { return nil }
        // op = BOOTREQUEST, Ethernet, 6-byte hardware address.
        guard bytes[0] == 1, bytes[1] == 1, bytes[2] == 6 else { return nil }
        guard Array(bytes[fixedBytes..<(fixedBytes + 4)]) == magicCookie else {
            return nil
        }
        let transactionID = UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16
            | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
        guard let clientMAC = MACAddress(bytes: Array(bytes[28..<34])) else {
            return nil
        }

        var type: MessageType?
        var requested: IPv4Address?
        var index = fixedBytes + magicCookie.count
        while index < bytes.count {
            let code = bytes[index]
            if code == 255 { break }        // end
            if code == 0 { index += 1; continue }   // pad
            guard index + 1 < bytes.count else { return nil }
            let length = Int(bytes[index + 1])
            let valueStart = index + 2
            guard valueStart + length <= bytes.count else { return nil }
            let value = Array(bytes[valueStart..<(valueStart + length)])
            switch code {
            case 53 where length == 1:
                type = MessageType(rawValue: value[0])
            case 50 where length == 4:
                requested = IPv4Address(bytes: value[0..<4])
            default:
                break
            }
            index = valueStart + length
        }
        guard let type else { return nil }
        return Message(
            type: type,
            transactionID: transactionID,
            clientMAC: clientMAC,
            requestedAddress: requested
        )
    }

    /// The reply to a client message, or nil when none is owed.
    ///
    /// A REQUEST naming an address other than the one this link uses is NAK'd
    /// rather than ignored, so a guest that remembers a lease from a previous
    /// network gives it up immediately instead of retrying until it times out.
    public static func reply(
        to message: Message,
        plan: GuestNetworkPlan,
        dnsServer: IPv4Address
    ) -> [UInt8]? {
        let responseType: MessageType
        switch message.type {
        case .discover:
            responseType = .offer
        case .request:
            if let requested = message.requestedAddress,
               requested != plan.guestAddress {
                responseType = .nak
            } else {
                responseType = .ack
            }
        case .inform:
            responseType = .ack
        default:
            // RELEASE and DECLINE need no answer; the address is fixed anyway.
            return nil
        }

        var out = [UInt8](repeating: 0, count: fixedBytes)
        out[0] = 2                                  // BOOTREPLY
        out[1] = 1
        out[2] = 6
        out[4] = UInt8(truncatingIfNeeded: message.transactionID >> 24)
        out[5] = UInt8(truncatingIfNeeded: message.transactionID >> 16)
        out[6] = UInt8(truncatingIfNeeded: message.transactionID >> 8)
        out[7] = UInt8(truncatingIfNeeded: message.transactionID)
        if responseType != .nak {
            out[16...19] = ArraySlice(plan.guestAddress.octets)   // yiaddr
        }
        out[20...23] = ArraySlice(plan.gatewayAddress.octets)     // siaddr
        out[28...33] = ArraySlice(message.clientMAC.bytes)
        out += magicCookie

        out += [53, 1, responseType.rawValue]
        out += [54, 4] + plan.gatewayAddress.octets               // server id
        if responseType != .nak {
            out += [51, 4,
                    UInt8(truncatingIfNeeded: plan.leaseSeconds >> 24),
                    UInt8(truncatingIfNeeded: plan.leaseSeconds >> 16),
                    UInt8(truncatingIfNeeded: plan.leaseSeconds >> 8),
                    UInt8(truncatingIfNeeded: plan.leaseSeconds)]
            out += [1, 4] + plan.netmask.octets                   // subnet mask
            out += [3, 4] + plan.gatewayAddress.octets            // router
            out += [6, 4] + dnsServer.octets                      // DNS
            // No option 121 and no option 33: a guest must not be handed extra
            // routes, and there is nowhere else on this link to route to.
        }
        out += [255]
        return out
    }
}
