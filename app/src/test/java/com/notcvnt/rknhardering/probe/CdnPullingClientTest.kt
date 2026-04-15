package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CdnPullingClientTest {

    @Test
    fun `parseCloudflareTrace extracts important fields`() {
        val parsed = CdnPullingClient.parseCloudflareTrace(
            """
                fl=933f48
                h=meduza.io
                ip=2a01:4f9:c013:d2ba::1
                colo=FRA
                loc=FI
                warp=off
            """.trimIndent(),
        )

        assertEquals("2a01:4f9:c013:d2ba::1", parsed?.ip)
        assertEquals("2a01:4f9:c013:d2ba::1", parsed?.importantFields?.get("IP"))
        assertEquals("FRA", parsed?.importantFields?.get("COLO"))
        assertEquals("FI", parsed?.importantFields?.get("LOC"))
        assertEquals("off", parsed?.importantFields?.get("WARP"))
    }

    @Test
    fun `parseCloudflareTrace returns null for invalid body`() {
        assertNull(CdnPullingClient.parseCloudflareTrace("not a trace body"))
    }

    @Test
    fun `parseCloudflareTrace ignores invalid ip field`() {
        val parsed = CdnPullingClient.parseCloudflareTrace("ip=blocked")

        assertNull(parsed)
    }

    @Test
    fun `parseGooglevideoReportMapping extracts first ip before mapping`() {
        val parsed = CdnPullingClient.parseGooglevideoReportMapping(
            """2a01:4f9:c013:d2ba::1 => hem08s05 : router: pf02.hem09""",
        )

        assertEquals("2a01:4f9:c013:d2ba::1", parsed?.ip)
        assertTrue(parsed?.importantFields?.isEmpty() == true)
    }

    @Test
    fun `parseGooglevideoReportMapping rejects body without ip prefix`() {
        assertNull(CdnPullingClient.parseGooglevideoReportMapping("router only without prefix"))
    }

    @Test
    fun `looksLikeIp rejects hostnames`() {
        assertFalse(CdnPullingClient.looksLikeIp("localhost"))
        assertFalse(CdnPullingClient.looksLikeIp("meduza.io"))
        assertFalse(CdnPullingClient.looksLikeIp("example.com"))
    }
}
