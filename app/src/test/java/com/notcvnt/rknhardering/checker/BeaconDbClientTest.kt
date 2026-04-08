package com.notcvnt.rknhardering.checker

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BeaconDbClientTest {

    @Test
    fun `exact response resolves country`() = runBlocking {
        val client = BeaconDbClient(
            countryResolver = { _, _ -> "ru" },
            request = { _, _, userAgent ->
                assertTrue(userAgent.startsWith("RKNHardering/"))
                BeaconDbClient.HttpResult(
                    code = 200,
                    body = """{"location":{"lat":55.7522,"lng":37.6156},"accuracy":120}""",
                )
            },
        )

        val result = client.lookup(listOf(cell()), emptyList())

        assertEquals("RU", result.countryCode)
        assertEquals("BeaconDB: exact match", result.summary)
        assertEquals(55.7522, result.latitude ?: 0.0, 0.0001)
        assertEquals(37.6156, result.longitude ?: 0.0, 0.0001)
    }

    @Test
    fun `ip fallback is ignored`() = runBlocking {
        val client = BeaconDbClient(
            countryResolver = { _, _ -> "ru" },
            request = { _, _, _ ->
                BeaconDbClient.HttpResult(
                    code = 200,
                    body = """{"location":{"lat":10.0,"lng":20.0},"fallback":"ipf"}""",
                )
            },
        )

        val result = client.lookup(listOf(cell()), emptyList())

        assertNull(result.countryCode)
        assertNull(result.latitude)
        assertNull(result.longitude)
        assertEquals("BeaconDB: IP fallback ignored", result.summary)
    }

    @Test
    fun `lacf fallback keeps coordinates but does not resolve country`() = runBlocking {
        val client = BeaconDbClient(
            countryResolver = { _, _ -> "ru" },
            request = { _, _, _ ->
                BeaconDbClient.HttpResult(
                    code = 200,
                    body = """{"location":{"lat":55.0,"lng":37.0},"fallback":"lacf"}""",
                )
            },
        )

        val result = client.lookup(listOf(cell()), emptyList())

        assertNull(result.countryCode)
        assertEquals("BeaconDB: coarse cell area fallback", result.summary)
        assertEquals(55.0, result.latitude ?: 0.0, 0.0001)
        assertEquals(37.0, result.longitude ?: 0.0, 0.0001)
    }

    @Test
    fun `insufficient radio data skips request`() = runBlocking {
        var called = false
        val client = BeaconDbClient(
            countryResolver = { _, _ -> "ru" },
            request = { _, _, _ ->
                called = true
                BeaconDbClient.HttpResult(200, "{}")
            },
        )

        val result = client.lookup(emptyList(), listOf(wifi()))

        assertFalse(called)
        assertEquals("BeaconDB: insufficient radio data", result.summary)
    }

    @Test
    fun `request body omits wifi payload when fewer than two access points`() {
        val client = BeaconDbClient(countryResolver = { _, _ -> null })

        val body = client.buildRequestBody(
            cells = listOf(cell()),
            wifiAccessPoints = listOf(wifi()),
        )

        assertFalse(body.contains("\"wifiAccessPoints\""))
        assertTrue(body.contains("\"cellTowers\":[{"))
    }

    @Test
    fun `unsupported radio types are excluded from payload`() {
        val client = BeaconDbClient(countryResolver = { _, _ -> null })

        val body = client.buildRequestBody(
            cells = listOf(cell(radio = "nr")),
            wifiAccessPoints = emptyList(),
        )

        assertTrue(body.contains("\"cellTowers\":[]"))
    }

    @Test
    fun `lookup surfaces rate limiting`() = runBlocking {
        val client = BeaconDbClient(
            countryResolver = { _, _ -> null },
            request = { _, _, _ -> BeaconDbClient.HttpResult(code = 429, body = "{}") },
        )

        val result = client.lookup(listOf(cell()), emptyList())

        assertEquals("BeaconDB: rate limited", result.summary)
    }

    @Test
    fun `lookup rejects non json success response`() = runBlocking {
        val client = BeaconDbClient(
            countryResolver = { _, _ -> null },
            request = { _, _, _ -> BeaconDbClient.HttpResult(code = 200, body = "<html></html>") },
        )

        val result = client.lookup(listOf(cell()), emptyList())

        assertEquals("BeaconDB: non-JSON response", result.summary)
    }

    @Test
    fun `lookup request includes consider ip false and disabled ip fallback`() = runBlocking {
        var capturedRequest = ""
        val client = BeaconDbClient(
            countryResolver = { _, _ -> null },
            request = { _, body, _ ->
                capturedRequest = body
                BeaconDbClient.HttpResult(
                    code = 200,
                    body = """{"location":{"lat":55.0,"lng":37.0}}""",
                )
            },
        )

        client.lookup(listOf(cell()), listOf(wifi(), wifi(mac = "11:22:33:44:55:66")))

        assertTrue(capturedRequest.contains("\"considerIp\":false"))
        assertTrue(capturedRequest.contains("\"fallbacks\":{\"lacf\":true,\"ipf\":false}"))
        assertTrue(capturedRequest.contains("\"wifiAccessPoints\":["))
        assertEquals(2, "\"macAddress\":".toRegex().findAll(capturedRequest).count())
    }

    private fun cell(radio: String = "lte"): CellLookupCandidate = CellLookupCandidate(
        radio = radio,
        mcc = "250",
        mnc = "1",
        areaCode = 12345,
        cellId = 67890,
        registered = true,
        signalStrength = -75,
    )

    private fun wifi(mac: String = "aa:bb:cc:dd:ee:ff"): WifiLookupCandidate = WifiLookupCandidate(
        macAddress = mac,
        frequency = 2412,
        signalStrength = -55,
    )
}
