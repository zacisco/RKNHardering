package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.XrayApiEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VerdictNarrativeTest {

    @Test
    fun `split tunnel confirmation is described as public ip only`() {
        val narrative = VerdictNarrativeBuilder.build(
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    directIp = "91.198.174.192",
                    proxyIp = "185.220.1.10",
                    evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS)),
                ),
            ),
        )

        assertEquals(ExposureStatus.PUBLIC_IP_ONLY, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("внешний IP"))
        assertTrue(narrative.discoveredRows.any { it.label == "Публичный IP напрямую" && it.value == "91.198.174.192" })
        assertTrue(narrative.discoveredRows.any { it.label == "Публичный IP через proxy" && it.value == "185.220.1.10" })
    }

    @Test
    fun `xray api endpoint is described as remote endpoint disclosure`() {
        val narrative = VerdictNarrativeBuilder.build(
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    xrayApiScanResult = XrayApiScanResult(
                        endpoint = XrayApiEndpoint(host = "127.0.0.1", port = 10085),
                        outbounds = listOf(
                            XrayOutboundSummary(
                                tag = "proxy",
                                protocolName = "vless",
                                address = "203.0.113.5",
                                port = 443,
                                uuid = null,
                                sni = null,
                                publicKey = null,
                                senderSettingsType = null,
                                proxySettingsType = null,
                            ),
                        ),
                    ),
                    evidence = listOf(evidence(EvidenceSource.XRAY_API)),
                ),
            ),
        )

        assertEquals(ExposureStatus.REMOTE_ENDPOINT_DISCOVERED, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("Xray API"))
        assertTrue(
            narrative.discoveredRows.any {
                it.label == "Адрес удалённого узла" && it.value == "203.0.113.5:443"
            },
        )
    }

    @Test
    fun `tun probe only is described as technical signal`() {
        val narrative = VerdictNarrativeBuilder.build(
            result = result(
                verdict = Verdict.NOT_DETECTED,
                bypass = bypass(
                    findings = listOf(
                        Finding(
                            description = "TUN активный зонд: запрос через VPN Network вернул IP 185.220.1.10",
                            isInformational = true,
                            source = EvidenceSource.TUN_ACTIVE_PROBE,
                        ),
                    ),
                ),
            ),
        )

        assertEquals(ExposureStatus.PUBLIC_IP_ONLY, narrative.exposureStatus)
        assertTrue(narrative.discoveredRows.any { it.label == "IP через VPN Network" })
    }

    @Test
    fun `local proxy without ips stays in local proxy status`() {
        val narrative = VerdictNarrativeBuilder.build(
            result = result(
                verdict = Verdict.NEEDS_REVIEW,
                bypass = bypass(
                    proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
                    needsReview = true,
                ),
            ),
        )

        assertEquals(ExposureStatus.LOCAL_PROXY_OR_API_ONLY, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("локальный proxy/API"))
        assertTrue(narrative.discoveredRows.any { it.label == "Локальный proxy" && it.value.contains("127.0.0.1:1080") })
    }

    @Test
    fun `privacy mode masks ip rows`() {
        val narrative = VerdictNarrativeBuilder.build(
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    directIp = "91.198.174.192",
                    proxyIp = "185.220.1.10",
                    evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS)),
                ),
            ),
            privacyMode = true,
        )

        val directRow = narrative.discoveredRows.first { it.label == "Публичный IP напрямую" }
        val proxyRow = narrative.discoveredRows.first { it.label == "Публичный IP через proxy" }

        assertEquals("91.198.*.*", directRow.value)
        assertEquals("185.220.*.*", proxyRow.value)
        assertFalse(proxyRow.value.contains("185.220.1.10"))
    }

    @Test
    fun `empty result falls back to insufficient data`() {
        val narrative = VerdictNarrativeBuilder.build(result())

        assertEquals(ExposureStatus.INSUFFICIENT_DATA, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("не нашла убедительных признаков"))
    }

    private fun result(
        verdict: Verdict = Verdict.NOT_DETECTED,
        geoIp: CategoryResult = category(),
        direct: CategoryResult = category(),
        indirect: CategoryResult = category(),
        location: CategoryResult = category(),
        ipComparison: IpComparisonResult = ipComparison(),
        bypass: BypassResult = bypass(),
    ): CheckResult = CheckResult(
        geoIp = geoIp,
        ipComparison = ipComparison,
        directSigns = direct,
        indirectSigns = indirect,
        locationSignals = location,
        bypassResult = bypass,
        verdict = verdict,
    )

    private fun category(
        detected: Boolean = false,
        needsReview: Boolean = false,
        findings: List<Finding> = emptyList(),
    ): CategoryResult = CategoryResult(
        name = "test",
        detected = detected,
        findings = findings,
        needsReview = needsReview,
        evidence = emptyList(),
    )

    private fun ipComparison(
        ruIp: String? = null,
        nonRuIp: String? = null,
        detected: Boolean = false,
        needsReview: Boolean = false,
    ): IpComparisonResult = IpComparisonResult(
        detected = detected,
        needsReview = needsReview,
        summary = "",
        ruGroup = IpCheckerGroupResult(
            title = "RU",
            detected = false,
            needsReview = false,
            statusLabel = "",
            summary = "",
            canonicalIp = ruIp,
            responses = listOf(
                IpCheckerResponse(
                    label = "ru",
                    url = "https://example.ru",
                    scope = IpCheckerScope.RU,
                    ip = ruIp,
                ),
            ),
        ),
        nonRuGroup = IpCheckerGroupResult(
            title = "NON_RU",
            detected = false,
            needsReview = false,
            statusLabel = "",
            summary = "",
            canonicalIp = nonRuIp,
            responses = listOf(
                IpCheckerResponse(
                    label = "non-ru",
                    url = "https://example.com",
                    scope = IpCheckerScope.NON_RU,
                    ip = nonRuIp,
                ),
            ),
        ),
    )

    private fun bypass(
        proxyEndpoint: ProxyEndpoint? = null,
        directIp: String? = null,
        proxyIp: String? = null,
        xrayApiScanResult: XrayApiScanResult? = null,
        findings: List<Finding> = emptyList(),
        detected: Boolean = false,
        needsReview: Boolean = false,
        evidence: List<EvidenceItem> = emptyList(),
    ): BypassResult = BypassResult(
        proxyEndpoint = proxyEndpoint,
        directIp = directIp,
        proxyIp = proxyIp,
        xrayApiScanResult = xrayApiScanResult,
        findings = findings,
        detected = detected || evidence.any { it.detected },
        needsReview = needsReview,
        evidence = evidence,
    )

    private fun evidence(source: EvidenceSource): EvidenceItem = EvidenceItem(
        source = source,
        detected = true,
        confidence = EvidenceConfidence.HIGH,
        description = source.name,
    )
}
