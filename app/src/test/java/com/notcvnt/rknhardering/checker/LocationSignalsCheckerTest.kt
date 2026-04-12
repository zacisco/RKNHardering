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
                simCards = listOf(sim(simMcc = "244", simCountryIso = "fi", operatorName = "Elisa", isRoaming = false)),
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
                simCards = listOf(sim(simMcc = "244", simCountryIso = "fi", operatorName = "Elisa", isRoaming = true)),
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
        assertTrue(infoFindings.any { it.description.startsWith("SIM[0] MCC:") })
        assertTrue(infoFindings.any { it.description.startsWith("SIM[0] Roaming:") })
        assertFalse(result.findings.any { it.description.startsWith("Cell lookup") && it.isInformational })
    }

    @Test
    fun `missing network mcc produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simCards = emptyList(),
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

    @Test
    fun `LocationSnapshot accepts simCards list`() {
        val sim = LocationSignalsChecker.SimCardInfo(
            slotIndex = 0,
            subscriptionId = 1,
            simMcc = "250",
            simCountryIso = "ru",
            operatorName = "MegaFon",
            isRoaming = false,
        )
        val s = LocationSignalsChecker.LocationSnapshot(
            networkMcc = "250",
            networkCountryIso = "ru",
            networkOperatorName = "MegaFon",
            simCards = listOf(sim),
            cellCountryCode = null,
            cellLookupSummary = null,
            cellCandidatesCount = 0,
            wifiAccessPointCandidatesCount = 0,
            bssid = null,
            cellLookupPermissionGranted = false,
            wifiPermissionGranted = false,
        )
        assertEquals(1, s.simCards.size)
    }

    @Test
    fun `dual sim with ru network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simCards = listOf(
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "250", simCountryIso = "ru", operatorName = "MegaFon", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = false),
                ),
            ),
        )

        assertFalse(result.needsReview)
        assertFalse(result.detected)
        assertTrue(result.findings.any { it.description.startsWith("SIM[0] MCC:") })
        assertTrue(result.findings.any { it.description.startsWith("SIM[1] MCC:") })
    }

    @Test
    fun `dual sim non-ru network with non-roaming matching sim gives medium confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "202",
                networkCountryIso = "gr",
                networkOperatorName = "Cosmote",
                simCards = listOf(
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "250", simCountryIso = "ru", operatorName = "MegaFon", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = false),
                ),
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
    fun `dual sim non-ru network with roaming matching sim gives low confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "202",
                networkCountryIso = "gr",
                networkOperatorName = "Cosmote",
                simCards = listOf(
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "250", simCountryIso = "ru", operatorName = "MegaFon", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = true),
                ),
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
    fun `empty sim cards list produces no sim findings and medium confidence for non-ru network`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simCards = emptyList(),
            ),
        )

        assertTrue(result.needsReview)
        assertFalse(result.findings.any { it.description.startsWith("SIM[") })
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    private fun sim(
        slotIndex: Int = 0,
        subscriptionId: Int = 1,
        simMcc: String? = "250",
        simCountryIso: String? = "ru",
        operatorName: String? = "MegaFon",
        isRoaming: Boolean? = false,
    ) = LocationSignalsChecker.SimCardInfo(
        slotIndex = slotIndex,
        subscriptionId = subscriptionId,
        simMcc = simMcc,
        simCountryIso = simCountryIso,
        operatorName = operatorName,
        isRoaming = isRoaming,
    )

    private fun snapshot(
        networkMcc: String? = "250",
        networkCountryIso: String? = "ru",
        networkOperatorName: String? = "MegaFon",
        simCards: List<LocationSignalsChecker.SimCardInfo> = listOf(sim()),
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
            simCards = simCards,
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
