package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.probe.XrayOutboundSummary

enum class ExposureStatus(val label: String) {
    REMOTE_ENDPOINT_DISCOVERED("Получен адрес удалённого узла"),
    PUBLIC_IP_ONLY("Получен только внешний IP"),
    LOCAL_PROXY_OR_API_ONLY("Найден только локальный proxy/API"),
    TECHNICAL_SIGNAL_ONLY("Есть только технические сетевые сигналы"),
    INSUFFICIENT_DATA("Данных о сервере не получено"),
}

data class NarrativeRow(
    val label: String,
    val value: String,
)

data class VerdictNarrative(
    val explanation: String,
    val exposureStatus: ExposureStatus,
    val meaningRows: List<String>,
    val discoveredRows: List<NarrativeRow>,
    val reasonRows: List<String>,
)

object VerdictNarrativeBuilder {

    private val ipv4Regex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    private val ipv6Regex = Regex("""(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])""")

    fun build(result: CheckResult, privacyMode: Boolean = false): VerdictNarrative {
        val snapshot = collectSnapshot(result)
        val exposureStatus = determineExposureStatus(snapshot)

        return VerdictNarrative(
            explanation = buildExplanation(result.verdict, exposureStatus),
            exposureStatus = exposureStatus,
            meaningRows = buildMeaningRows(result.verdict, exposureStatus),
            discoveredRows = buildDiscoveredRows(snapshot, exposureStatus, privacyMode),
            reasonRows = buildReasonRows(result),
        )
    }

    private fun collectSnapshot(result: CheckResult): Snapshot {
        val xrayApi = result.bypassResult.xrayApiScanResult
        val gatewayLeakFinding = result.bypassResult.findings.firstOrNull {
            it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected
        }
        val gatewayLeakIps = gatewayLeakFinding?.description?.let(::extractIps).orEmpty()
        val vpnProbeFinding = result.bypassResult.findings.firstOrNull {
            (it.source == EvidenceSource.VPN_NETWORK_BINDING || it.source == EvidenceSource.TUN_ACTIVE_PROBE) &&
                extractIps(it.description).isNotEmpty()
        }

        val defaultNonVpnIp = result.bypassResult.findings.firstOrNull {
            it.description.startsWith("Default non-VPN IP:")
        }?.description?.let(::extractIps)?.firstOrNull()

        return Snapshot(
            remoteEndpoints = xrayApi?.outbounds.orEmpty().mapNotNull(::formatRemoteEndpoint).distinct(),
            localApiEndpoint = xrayApi?.endpoint?.let { formatHostPort(it.host, it.port) },
            localProxyEndpoint = result.bypassResult.proxyEndpoint?.let {
                "${it.type.name} ${formatHostPort(it.host, it.port)}"
            },
            vpnNetworkIp = gatewayLeakIps.getOrNull(0)
                ?: vpnProbeFinding?.description?.let(::extractIps)?.firstOrNull(),
            realIp = gatewayLeakIps.getOrNull(1) ?: defaultNonVpnIp,
            directIp = result.bypassResult.directIp,
            proxyIp = result.bypassResult.proxyIp,
            geoIp = extractGeoIp(result.geoIp),
            ruCheckerIp = result.ipComparison.ruGroup.canonicalIp,
            nonRuCheckerIp = result.ipComparison.nonRuGroup.canonicalIp,
            technicalSignalsPresent = hasTechnicalSignals(result),
        )
    }

    private fun determineExposureStatus(snapshot: Snapshot): ExposureStatus {
        return when {
            snapshot.remoteEndpoints.isNotEmpty() -> ExposureStatus.REMOTE_ENDPOINT_DISCOVERED
            snapshot.hasPublicIp -> ExposureStatus.PUBLIC_IP_ONLY
            snapshot.localApiEndpoint != null || snapshot.localProxyEndpoint != null ->
                ExposureStatus.LOCAL_PROXY_OR_API_ONLY
            snapshot.technicalSignalsPresent -> ExposureStatus.TECHNICAL_SIGNAL_ONLY
            else -> ExposureStatus.INSUFFICIENT_DATA
        }
    }

    private fun buildExplanation(verdict: Verdict, exposureStatus: ExposureStatus): String {
        val base = when (verdict) {
            Verdict.DETECTED -> "Автоматическая проверка считает обход подтверждённым."
            Verdict.NEEDS_REVIEW -> "Автоматической проверки недостаточно для однозначного вывода."
            Verdict.NOT_DETECTED -> "Проверка не нашла убедительных признаков обхода."
        }
        val exposure = when (exposureStatus) {
            ExposureStatus.REMOTE_ENDPOINT_DISCOVERED ->
                "Удалось получить адрес удалённого узла из локального Xray API."
            ExposureStatus.PUBLIC_IP_ONLY ->
                "Удалось увидеть только внешний IP выхода, но не адрес конечного сервера."
            ExposureStatus.LOCAL_PROXY_OR_API_ONLY ->
                "Удалось увидеть только локальный proxy/API на устройстве, без адреса удалённого узла."
            ExposureStatus.TECHNICAL_SIGNAL_ONLY ->
                "Есть только технические сигналы сети и маршрутов, без адреса сервера."
            ExposureStatus.INSUFFICIENT_DATA ->
                "Адрес сервера или внешний IP получить не удалось."
        }
        return "$base $exposure"
    }

    private fun buildMeaningRows(verdict: Verdict, exposureStatus: ExposureStatus): List<String> {
        val verdictMeaning = when (verdict) {
            Verdict.DETECTED -> "Красный вердикт означает, что автоматическая проверка собрала достаточные признаки обхода."
            Verdict.NEEDS_REVIEW -> "Жёлтый вердикт означает, что сигналы есть, но их нужно перепроверить вручную."
            Verdict.NOT_DETECTED -> "Зелёный вердикт означает, что решающие сигналы обхода не найдены."
        }
        val exposureMeaning = when (exposureStatus) {
            ExposureStatus.REMOTE_ENDPOINT_DISCOVERED ->
                "Удалось получить именно адрес удалённого узла, а не только внешний IP."
            ExposureStatus.PUBLIC_IP_ONLY ->
                "Внешний IP и адрес конечного сервера не одно и то же: внешний IP видят интернет-сервисы, но это может быть только точка выхода."
            ExposureStatus.LOCAL_PROXY_OR_API_ONLY ->
                "Локальный proxy/API говорит о механизме обхода на устройстве, но сам по себе не раскрывает удалённый сервер."
            ExposureStatus.TECHNICAL_SIGNAL_ONLY ->
                "Технические сигналы подтверждают сетевое поведение, но не дают адрес удалённого узла."
            ExposureStatus.INSUFFICIENT_DATA ->
                "По текущим данным нельзя сказать, удалось ли приложению узнать адрес сервера обхода."
        }
        return listOf(verdictMeaning, exposureMeaning)
    }

    private fun buildDiscoveredRows(
        snapshot: Snapshot,
        exposureStatus: ExposureStatus,
        privacyMode: Boolean,
    ): List<NarrativeRow> {
        val rows = mutableListOf<NarrativeRow>()

        fun addRow(label: String, value: String?) {
            if (value.isNullOrBlank()) return
            rows += NarrativeRow(label, maybeMask(value, privacyMode))
        }

        addRow("Уровень раскрытия", exposureStatus.label)
        addRow("Локальный Xray API", snapshot.localApiEndpoint)

        snapshot.remoteEndpoints.take(3).forEachIndexed { index, endpoint ->
            addRow(
                if (index == 0) "Адрес удалённого узла" else "Доп. адрес удалённого узла",
                endpoint,
            )
        }

        addRow("Локальный proxy", snapshot.localProxyEndpoint)
        addRow("IP через VPN Network", snapshot.vpnNetworkIp)
        addRow("IP вне VPN", snapshot.realIp)
        addRow("Публичный IP напрямую", snapshot.directIp)
        addRow("Публичный IP через proxy", snapshot.proxyIp)

        if (!snapshot.ruCheckerIp.isNullOrBlank() && snapshot.ruCheckerIp == snapshot.nonRuCheckerIp) {
            addRow("IP по внешним чекерам", snapshot.ruCheckerIp)
        } else {
            addRow("IP RU-чекеров", snapshot.ruCheckerIp)
            addRow("IP не-RU чекеров", snapshot.nonRuCheckerIp)
        }

        addRow("IP из GeoIP", snapshot.geoIp)
        return rows
    }

    private fun buildReasonRows(result: CheckResult): List<String> {
        val reasons = linkedSetOf<String>()

        if (hasBypassEvidence(result.bypassResult, EvidenceSource.XRAY_API)) {
            reasons += "На устройстве найден локальный Xray API, из которого читаются outbound-адреса."
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.SPLIT_TUNNEL_BYPASS)) {
            reasons += "Прямой IP и IP через локальный proxy различаются."
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.VPN_GATEWAY_LEAK)) {
            reasons += "При активном VPN приложение смогло выйти через non-VPN сеть."
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.VPN_NETWORK_BINDING)) {
            reasons += "Приложение смогло использовать объект VPN Network отдельно от обычной сети."
        }
        if (result.bypassResult.needsReview) {
            reasons += "Найден локальный proxy, но обход не подтвердился автоматически."
        }
        if (result.ipComparison.detected) {
            reasons += "RU и не-RU IP-чекеры вернули разные внешние IP."
        } else if (result.ipComparison.needsReview) {
            reasons += "Внешние IP-чекеры ответили неполно или противоречиво."
        }

        val foreignGeoSignal = result.geoIp.needsReview || result.geoIp.evidence.any {
            it.source == EvidenceSource.GEO_IP && it.detected
        }
        val locationConfirmsRussia = result.locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true") ||
                it.description.contains("cell_country_ru:true") ||
                it.description.contains("location_country_ru:true")
        }
        if (foreignGeoSignal && locationConfirmsRussia) {
            reasons += "Сигналы местоположения указывают на Россию, а GeoIP — на внешний адрес."
        } else if (foreignGeoSignal) {
            reasons += "GeoIP даёт внешний или подозрительный адрес."
        }

        if (result.directSigns.detected) {
            reasons += "Найдены прямые признаки локального proxy/VPN."
        }
        if (result.indirectSigns.detected) {
            reasons += "Найдены косвенные признаки туннеля, маршрутов или DNS-подмены."
        }

        if (reasons.isEmpty()) {
            reasons += when (result.verdict) {
                Verdict.DETECTED -> "Вердикт собран из сочетания нескольких сигналов проверки."
                Verdict.NEEDS_REVIEW -> "Сигналы частичные или противоречивые, поэтому нужен ручной разбор."
                Verdict.NOT_DETECTED -> "Решающие сигналы обхода не найдены."
            }
        }

        return reasons.take(5)
    }

    private fun extractGeoIp(result: CategoryResult): String? {
        return result.findings.firstOrNull {
            it.isInformational && it.description.startsWith("IP:")
        }?.description?.substringAfter("IP:")?.trim()
    }

    private fun hasTechnicalSignals(result: CheckResult): Boolean {
        return result.directSigns.detected ||
            result.directSigns.needsReview ||
            result.indirectSigns.detected ||
            result.indirectSigns.needsReview ||
            result.geoIp.detected ||
            result.geoIp.needsReview ||
            result.locationSignals.detected ||
            result.locationSignals.needsReview ||
            result.ipComparison.detected ||
            result.ipComparison.needsReview ||
            result.bypassResult.findings.any {
                it.source == EvidenceSource.TUN_ACTIVE_PROBE ||
                    it.source == EvidenceSource.VPN_NETWORK_BINDING ||
                    it.source == EvidenceSource.VPN_GATEWAY_LEAK
            } ||
            result.bypassResult.evidence.any { it.detected }
    }

    private fun hasBypassEvidence(result: BypassResult, source: EvidenceSource): Boolean {
        return result.evidence.any { it.source == source && it.detected } ||
            result.findings.any { it.source == source && it.detected }
    }

    private fun formatRemoteEndpoint(outbound: XrayOutboundSummary): String? {
        val host = outbound.address ?: outbound.sni ?: return null
        return formatHostPort(host, outbound.port)
    }

    private fun formatHostPort(host: String, port: Int?): String {
        val renderedHost = if (host.contains(':') && !host.startsWith("[")) {
            "[$host]"
        } else {
            host
        }
        return if (port != null) "$renderedHost:$port" else renderedHost
    }

    private fun extractIps(text: String): List<String> {
        val ipv4 = ipv4Regex.findAll(text).map { it.value }.toList()
        val ipv6 = ipv6Regex.findAll(text).map { it.value }.toList()
        return (ipv4 + ipv6).distinct()
    }

    private fun maybeMask(value: String, privacyMode: Boolean): String {
        if (!privacyMode) return value
        val maskedIpv4 = ipv4Regex.replace(value) { maskIpv4(it.value) }
        return ipv6Regex.replace(maskedIpv4) { maskIpv6(it.value) }
    }

    private fun maskIpv4(value: String): String {
        val parts = value.split(".")
        if (parts.size != 4) return value
        return "${parts[0]}.${parts[1]}.*.*"
    }

    private fun maskIpv6(value: String): String {
        val parts = value.trim('[', ']').split(':').filter { it.isNotEmpty() }
        if (parts.isEmpty()) return "*:*:*:*"
        val visible = parts.take(4)
        return visible.joinToString(":") + ":*:*:*:*"
    }

    private data class Snapshot(
        val remoteEndpoints: List<String>,
        val localApiEndpoint: String?,
        val localProxyEndpoint: String?,
        val vpnNetworkIp: String?,
        val realIp: String?,
        val directIp: String?,
        val proxyIp: String?,
        val geoIp: String?,
        val ruCheckerIp: String?,
        val nonRuCheckerIp: String?,
        val technicalSignalsPresent: Boolean,
    ) {
        val hasPublicIp: Boolean
            get() = listOf(
                vpnNetworkIp,
                realIp,
                directIp,
                proxyIp,
                geoIp,
                ruCheckerIp,
                nonRuCheckerIp,
            ).any { !it.isNullOrBlank() }
    }
}
