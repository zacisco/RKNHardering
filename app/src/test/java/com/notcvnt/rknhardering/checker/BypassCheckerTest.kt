package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BypassCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `explicit vpn network binding on non vpn default network is detected`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
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

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.description.contains("VPN network binding") })
    }

    @Test
    fun `underlying reachability is treated as gateway leak only when default network is vpn`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
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

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `tun probe success is reported as informational finding`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "185.220.1.10",
                underlyingIp = null,
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("185.220.1.10")
            },
        )
    }

    @Test
    fun `vpn network binding requires verified underlying internet path`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "185.220.1.10",
                underlyingIp = null,
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(
            findings.any {
                it.needsReview &&
                    it.source == EvidenceSource.VPN_NETWORK_BINDING &&
                    it.description.contains("manual review")
            },
        )
    }

    @Test
    fun `tun probe failure reason is recorded when vpn path fails`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = null,
                underlyingIp = null,
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("timeout")
            },
        )
    }

    @Test
    fun `gateway leak requires vpn and underlying ip comparison`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = null,
                underlyingIp = "91.198.174.192",
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(
            findings.any {
                it.source == EvidenceSource.VPN_GATEWAY_LEAK &&
                    it.needsReview &&
                    it.description.contains("91.198.174.192")
            },
        )
    }

    @Test
    fun `gateway leak not detected when vpn ip and underlying ip are the same`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
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

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
    }

    @Test
    fun `vpn network binding is not detected when default and vpn ips match`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "203.0.113.10",
                underlyingIp = "203.0.113.10",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_NETWORK_BINDING })
    }
}
