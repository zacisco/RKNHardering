package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.network.DnsResolverConfig
import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CdnPullingCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `evaluate marks result detected when at least one target exposes data`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "rutracker.org",
                    url = "https://rutracker.org/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                    rawBody = "ip=203.0.113.64\nloc=FI",
                ),
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    error = "timeout",
                ),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertFalse(result.hasError)
    }

    @Test
    fun `evaluate marks result as error when no usable data is returned`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    rawBody = "unknown body",
                    error = "unrecognized",
                ),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.hasError)
        assertFalse(result.needsReview)
    }

    @Test
    fun `evaluate uses no-ip summary when trace data is partial`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "rutracker.org",
                    url = "https://rutracker.org/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                ),
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    importantFields = linkedMapOf("LOC" to "NL", "COLO" to "AMS"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertEquals(
            context.getString(R.string.checker_cdn_pulling_summary_detected_no_ip, 2, 2),
            result.summary,
        )
        assertTrue(result.findings.any { it.description == "rutracker.org: IP: 203.0.113.64, LOC: FI" })
    }

    @Test
    fun `fetchBodyWithRetries retries transient failures and returns success`() = runBlocking {
        var attempts = 0

        val result = CdnPullingChecker.fetchBodyWithRetries(
            endpoint = "https://meduza.io/cdn-cgi/trace",
            timeoutMs = 1000,
            resolverConfig = DnsResolverConfig.system(),
            maxAttempts = 3,
            retryDelayMs = 0,
        ) { _, _, _ ->
            attempts += 1
            if (attempts < 3) {
                Result.failure(IOException("timeout"))
            } else {
                Result.success("ip=203.0.113.64")
            }
        }

        assertTrue(result.isSuccess)
        assertEquals("ip=203.0.113.64", result.getOrNull())
        assertEquals(3, attempts)
    }
}
