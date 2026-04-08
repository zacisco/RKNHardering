package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GeoIpCheckerTest {

    @Test
    fun `foreign residential ip requires review but is not detected`() {
        val result = GeoIpChecker.evaluate(
            GeoIpChecker.GeoIpSnapshot(
                ip = "11.22.33.44",
                country = "China",
                countryCode = "CN",
                isp = "China Mobile",
                org = "China Mobile",
                asn = "AS4134",
                isProxy = false,
                isHosting = false,
                hostingVotes = 0,
                hostingSources = emptyList(),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.evidence.isEmpty())
        assertTrue(result.findings.any { it.source == EvidenceSource.GEO_IP && it.needsReview })
    }

    @Test
    fun `hosting or proxy still count as detected geo risk`() {
        val result = GeoIpChecker.evaluate(
            GeoIpChecker.GeoIpSnapshot(
                ip = "22.33.44.55",
                country = "Russia",
                countryCode = "RU",
                isp = "Example ISP",
                org = "Example Org",
                asn = "AS12345",
                isProxy = true,
                isHosting = true,
                hostingVotes = 3,
                hostingSources = listOf("ip-api.com", "ipapi.is", "iplocate.io"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertEquals(2, result.evidence.count { it.source == EvidenceSource.GEO_IP })
    }
}
