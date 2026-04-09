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
        val result = LocationSignalsChecker.evaluate(snapshot())

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("MegaFon") })
        assertTrue(result.findings.any { it.description == "network_mcc_ru:true" })
    }

    @Test
    fun `foreign network mcc sets needs review`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "244",
                simCountryIso = "fi",
            ),
        )

        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `foreign network mcc with roaming lowers confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = true,
            ),
        )

        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }

    @Test
    fun `plmn fields are marked as informational`() {
        val result = LocationSignalsChecker.evaluate(snapshot())

        val infoFindings = result.findings.filter { it.isInformational }
        assertEquals(4, infoFindings.size)
        assertTrue(infoFindings.any { it.description.startsWith("Network operator:") })
        assertTrue(infoFindings.any { it.description.startsWith("Network MCC:") })
        assertTrue(infoFindings.any { it.description.startsWith("SIM MCC:") })
        assertTrue(infoFindings.any { it.description.startsWith("Roaming:") })
        assertFalse(result.findings.any { it.description.startsWith("Cell lookup") && it.isInformational })
    }

    @Test
    fun `missing network mcc produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
            ),
        )

        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description == "PLMN: network MCC is unavailable" })
    }

    @Test
    fun `cell lookup without location permission is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(cellLookupPermissionGranted = false))

        assertTrue(result.findings.any { it.description.contains("ACCESS_FINE_LOCATION") })
    }

    @Test
    fun `cell lookup with no candidates is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 0,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("base station identifiers are unavailable") })
    }

    @Test
    fun `wifi permission absence is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(wifiPermissionGranted = false))

        assertTrue(result.findings.any { it.description == "Wi-Fi scan: permissions are not granted" })
        assertTrue(result.findings.any { it.description == "BSSID: permission is not granted" })
    }

    @Test
    fun `wifi candidate count is surfaced`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                wifiAccessPointCandidatesCount = 4,
            ),
        )

        assertTrue(result.findings.any { it.description == "Wi-Fi scan candidates: 4" })
    }

    @Test
    fun `ru cell lookup adds russian markers`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellCountryCode = "RU",
                cellLookupSummary = "BeaconDB: exact match",
            ),
        )

        assertTrue(result.findings.any { it.description == "cell_country_ru:true" })
        assertTrue(result.findings.any { it.description == "location_country_ru:true" })
        assertTrue(result.findings.any { it.description.contains("BeaconDB: exact match") })
    }

    @Test
    fun `coarse BeaconDB fallback does not add russian markers`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellLookupSummary = "BeaconDB: coarse cell area fallback",
            ),
        )

        assertFalse(result.findings.any { it.description == "cell_country_ru:true" })
        assertFalse(result.findings.any { it.description == "location_country_ru:true" })
    }

    @Test
    fun `valid bssid is surfaced as informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                bssid = "AA:BB:CC:DD:EE:FF",
            ),
        )

        assertTrue(result.findings.any { it.description.contains("AA:BB:CC:DD:EE:FF") })
    }

    @Test
    fun `placeholder bssid is treated as unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                bssid = "02:00:00:00:00:00",
            ),
        )

        assertTrue(result.findings.any { it.description == "BSSID: unavailable" })
    }

    private fun snapshot(
        networkMcc: String? = "250",
        networkCountryIso: String? = "ru",
        networkOperatorName: String? = "MegaFon",
        simMcc: String? = "250",
        simCountryIso: String? = "ru",
        isRoaming: Boolean? = false,
        cellCountryCode: String? = null,
        cellLookupSummary: String? = null,
        cellCandidatesCount: Int = 0,
        wifiAccessPointCandidatesCount: Int = 0,
        bssid: String? = null,
        cellLookupPermissionGranted: Boolean = false,
        wifiPermissionGranted: Boolean = false,
    ): LocationSignalsChecker.LocationSnapshot {
        return LocationSignalsChecker.LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simMcc = simMcc,
            simCountryIso = simCountryIso,
            isRoaming = isRoaming,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            wifiAccessPointCandidatesCount = wifiAccessPointCandidatesCount,
            bssid = bssid,
            cellLookupPermissionGranted = cellLookupPermissionGranted,
            wifiPermissionGranted = wifiPermissionGranted,
        )
    }
}
