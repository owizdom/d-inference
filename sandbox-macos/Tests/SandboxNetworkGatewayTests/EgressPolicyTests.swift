import Foundation
import XCTest

@testable import SandboxNetworkGateway

final class EgressPolicyTests: XCTestCase {
    private let open = EgressPolicy(egressEnabled: true)

    /// The addresses that lead back to the provider, its neighbours, or a
    /// cloud credential endpoint. Each one is a way out of the sandbox.
    func testTheAddressesThatMatterAreDenied() {
        let mustDeny = [
            "10.0.0.1", "10.255.255.254",           // RFC1918
            "172.16.0.1", "172.31.255.254",         // RFC1918
            "192.168.1.1", "192.168.64.22",         // RFC1918, incl. VM subnets
            "127.0.0.1",                            // the host itself
            "169.254.169.254",                      // cloud metadata
            "169.254.0.1",                          // link-local
            "0.0.0.0",
            "255.255.255.255",                      // broadcast
            "224.0.0.251",                          // mDNS multicast
            "100.64.0.1",                           // CGNAT
        ]
        for text in mustDeny {
            let address = IPv4Address(text)!
            guard case .deny = open.decide(destination: address) else {
                return XCTFail("\(text) must be denied")
            }
        }
    }

    /// The test above is worthless if everything is denied, so pin the
    /// positive: ordinary public addresses are reachable.
    func testPublicAddressesAreAllowed() {
        for text in ["1.1.1.1", "8.8.8.8", "140.82.121.4", "93.184.216.34"] {
            let address = IPv4Address(text)!
            XCTAssertEqual(
                open.decide(destination: address), .allow,
                "\(text) should be reachable"
            )
        }
    }

    /// Boundaries are where range checks go wrong, so walk the edges of the
    /// RFC1918 blocks rather than sampling their middles.
    func testRangeBoundariesAreExact() {
        // 172.16.0.0/12 spans 172.16.x to 172.31.x and no further.
        guard case .deny = open.decide(destination: IPv4Address("172.16.0.0")!)
        else { return XCTFail("172.16.0.0 is inside") }
        guard case .deny = open.decide(destination: IPv4Address("172.31.255.255")!)
        else { return XCTFail("172.31.255.255 is inside") }
        XCTAssertEqual(
            open.decide(destination: IPv4Address("172.15.255.255")!), .allow
        )
        XCTAssertEqual(
            open.decide(destination: IPv4Address("172.32.0.0")!), .allow
        )
    }

    /// Default-deny is a starting state, not a setting. A sandbox admitted
    /// before its policy arrives must reach nothing.
    func testNothingIsReachableUntilAPolicyIsInstalled() {
        guard case .deny(let reason) =
            EgressPolicy.denyAll.decide(destination: IPv4Address("1.1.1.1")!)
        else {
            return XCTFail("a gateway with no policy must deny")
        }
        XCTAssertTrue(reason.contains("not installed"), reason)
    }

    /// A deployment can deny more, and the unconditional set stays denied
    /// regardless of what anyone configures.
    func testAdditionalRangesNarrowButNeverWiden() {
        let policy = EgressPolicy(
            egressEnabled: true,
            additionalDenied: [IPv4Prefix("93.184.216.0/24")!]
        )
        guard case .deny = policy.decide(destination: IPv4Address("93.184.216.34")!)
        else { return XCTFail("an additional range must be denied") }
        XCTAssertEqual(
            policy.decide(destination: IPv4Address("1.1.1.1")!), .allow
        )
        // Adding ranges cannot re-open a reserved one.
        guard case .deny = policy.decide(destination: IPv4Address("10.0.0.1")!)
        else { return XCTFail("reserved ranges stay denied") }
    }

    func testPrefixMathAtTheExtremes() {
        // /0 matches everything, /32 matches exactly one address.
        XCTAssertTrue(IPv4Prefix("0.0.0.0/0")!.contains(IPv4Address("8.8.8.8")!))
        let single = IPv4Prefix("8.8.8.8/32")!
        XCTAssertTrue(single.contains(IPv4Address("8.8.8.8")!))
        XCTAssertFalse(single.contains(IPv4Address("8.8.8.9")!))
        XCTAssertNil(IPv4Prefix("8.8.8.8/33"))
        XCTAssertNil(IPv4Prefix("not-an-address/8"))
    }
}
