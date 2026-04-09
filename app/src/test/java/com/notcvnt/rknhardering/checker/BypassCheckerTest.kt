package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BypassCheckerTest {

    @Test
    fun `explicit vpn network binding on non vpn default network is detected`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "185.220.1.10",
                underlyingIp = "91.198.174.192",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(detected)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.description.contains("VPN network binding") })
    }

    @Test
    fun `underlying reachability is treated as gateway leak only when default network is vpn`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "185.220.1.10",
                underlyingIp = "91.198.174.192",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(detected)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `gateway leak not detected when vpn ip and underlying ip are the same`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "128.71.10.5",
                underlyingIp = "128.71.10.5",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(detected)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
    }
}
