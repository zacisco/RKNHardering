package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocationSignalsCheckerTest {

    @Test
    fun `russian network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("MegaFon") })
        assertTrue(result.findings.any { it.description.contains("ru", ignoreCase = true) })
    }

    @Test
    fun `foreign network mcc sets needsReview`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "244",
                simCountryIso = "fi",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `foreign sim roaming in russia produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "Beeline",
                simMcc = "244",
                simCountryIso = "fi",
                isRoaming = true,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
    }

    @Test
    fun `no sim produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.isEmpty())
    }

    @Test
    fun `phone permission denied skips plmn block`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
                bssid = null,
                phonePermissionGranted = false,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("разрешение", ignoreCase = true) })
    }

    @Test
    fun `location permission denied skips bssid block`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("разрешение", ignoreCase = true) })
    }

    @Test
    fun `valid bssid produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = "AA:BB:CC:DD:EE:FF",
                phonePermissionGranted = true,
                locationPermissionGranted = true,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("AA:BB:CC:DD:EE:FF") })
    }

    @Test
    fun `placeholder bssid 020000000000 treated as unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = "02:00:00:00:00:00",
                phonePermissionGranted = true,
                locationPermissionGranted = true,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("недоступен") })
    }

    @Test
    fun `foreign network mcc with roaming has lower confidence`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = true,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }
}
