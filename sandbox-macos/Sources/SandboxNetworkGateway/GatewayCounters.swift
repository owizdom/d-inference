import Foundation

/// What the gateway did, so "filtered" and "broken" are distinguishable.
///
/// A dropped packet with no record is indistinguishable from a gateway that
/// stopped working, and the difference matters at three in the morning.
public struct GatewayCounters: Equatable, Sendable {
    public var framesReceived = 0
    public var framesSent = 0
    public var arpAnswered = 0
    public var dhcpAnswered = 0
    public var icmpAnswered = 0
    public var udpRelayed = 0
    public var deniedByPolicy = 0
    public var droppedUnsupported = 0
    public var droppedMalformed = 0
    public var droppedIPv6 = 0

    public init() {}

    public var summary: String {
        "rx=\(framesReceived) tx=\(framesSent) arp=\(arpAnswered) "
            + "dhcp=\(dhcpAnswered) icmp=\(icmpAnswered) udp=\(udpRelayed) "
            + "denied=\(deniedByPolicy) ipv6=\(droppedIPv6) "
            + "unsupported=\(droppedUnsupported) malformed=\(droppedMalformed)"
    }
}
