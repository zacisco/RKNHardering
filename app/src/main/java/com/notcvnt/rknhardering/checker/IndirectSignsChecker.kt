package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import com.notcvnt.rknhardering.vpn.VpnDumpsysParser
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.NetworkInterface

object IndirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal enum class DnsClassification {
        LOOPBACK,
        PRIVATE_LAN,
        PRIVATE_TUNNEL,
        KNOWN_PUBLIC_RESOLVER,
        LINK_LOCAL,
        OTHER_PUBLIC,
    }

    internal enum class DnsSignalStatus {
        CLEAR,
        NEEDS_REVIEW,
        DETECTED,
    }

    private val VPN_INTERFACE_PATTERNS = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
        Regex("^ipsec.*"),
    )

    private val STANDARD_INTERFACES = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$"),
    )

    private val KNOWN_PUBLIC_RESOLVERS = setOf(
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15",
        "77.88.8.8", "77.88.8.1",
        "76.76.19.19",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
        "2620:119:35::35", "2620:119:53::53",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    )

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val activeApps = mutableListOf<ActiveVpnApp>()
        var detected = false
        var needsReview = false

        val notVpnOutcome = checkNotVpnCapability(context, findings, evidence)
        detected = detected || notVpnOutcome.detected

        detected = checkNetworkInterfaces(findings, evidence) || detected
        detected = checkMtu(findings, evidence) || detected
        detected = checkRoutingTable(findings, evidence) || detected

        val dnsOutcome = checkDns(context, findings, evidence)
        detected = detected || dnsOutcome.detected
        needsReview = needsReview || dnsOutcome.needsReview

        val dumpsysVpnOutcome = checkDumpsysVpn(findings, evidence, activeApps)
        detected = detected || dumpsysVpnOutcome.detected
        needsReview = needsReview || dumpsysVpnOutcome.needsReview

        val dumpsysServiceOutcome = checkDumpsysVpnService(findings, evidence, activeApps)
        detected = detected || dumpsysServiceOutcome.detected
        needsReview = needsReview || dumpsysServiceOutcome.needsReview

        return CategoryResult(
            name = "Косвенные признаки",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            activeApps = activeApps.distinctBy { Triple(it.packageName, it.serviceName, it.source) },
        )
    }

    private fun checkNotVpnCapability(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return SignalOutcome()
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return SignalOutcome()

        val capsString = caps.toString()
        val hasNotVpn = capsString.contains("NOT_VPN")
        findings.add(
            Finding(
                description = "Capability NOT_VPN: ${if (hasNotVpn) "присутствует" else "отсутствует (подозрительно)"}",
                detected = !hasNotVpn,
                source = EvidenceSource.NETWORK_CAPABILITIES,
                confidence = (!hasNotVpn).takeIf { it }?.let { EvidenceConfidence.MEDIUM },
            ),
        )
        if (!hasNotVpn) {
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Active network does not expose NOT_VPN capability",
                ),
            )
        }
        return SignalOutcome(detected = !hasNotVpn)
    }

    private fun checkNetworkInterfaces(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            val vpnInterfaces = interfaces.filter { iface ->
                iface.isUp && VPN_INTERFACE_PATTERNS.any { pattern -> pattern.matches(iface.name) }
            }

            if (vpnInterfaces.isEmpty()) {
                findings.add(Finding("VPN-интерфейсы (tun/tap/wg/ppp/ipsec): не обнаружены"))
                return false
            }

            for (iface in vpnInterfaces) {
                findings.add(
                    Finding(
                        description = "VPN-интерфейс обнаружен: ${iface.name}",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Active VPN-like interface ${iface.name}",
                    ),
                )
            }
            true
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке интерфейсов: ${e.message}"))
            false
        }
    }

    private fun checkMtu(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            var detected = false
            for (iface in interfaces) {
                if (!iface.isUp) continue
                val isVpnLike = VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) }
                if (!isVpnLike) continue

                val mtu = iface.mtu
                if (mtu !in 1..1499) continue

                findings.add(
                    Finding(
                        description = "MTU аномалия: ${iface.name} MTU=$mtu (< 1500)",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "VPN-like interface ${iface.name} uses low MTU $mtu",
                    ),
                )
                detected = true
            }

            val activeInterfaces = interfaces.filter { it.isUp && it.mtu in 1..1499 }
            val nonVpnLowMtu = activeInterfaces.filter { iface ->
                !VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) } &&
                    !STANDARD_INTERFACES.any { it.matches(iface.name) }
            }
            for (iface in nonVpnLowMtu) {
                findings.add(
                    Finding(
                        description = "MTU аномалия: нестандартный интерфейс ${iface.name} MTU=${iface.mtu}",
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.LOW,
                        description = "Non-standard interface ${iface.name} uses low MTU ${iface.mtu}",
                    ),
                )
                detected = true
            }

            if (!detected) {
                findings.add(Finding("MTU: аномалий не обнаружено"))
            }

            detected
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке MTU: ${e.message}"))
            false
        }
    }

    private fun checkRoutingTable(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        return try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists()) {
                findings.add(Finding("Таблица маршрутизации: /proc/net/route недоступен"))
                return false
            }

            val lines = BufferedReader(FileReader(routeFile)).use { it.readLines() }
            val defaultRoutes = lines.drop(1).filter { line ->
                val parts = line.trim().split("\\s+".toRegex())
                parts.size >= 2 && parts[1] == "00000000"
            }

            if (defaultRoutes.isEmpty()) {
                findings.add(Finding("Маршрут по умолчанию: не найден"))
                return false
            }

            var detected = false
            for (route in defaultRoutes) {
                val parts = route.trim().split("\\s+".toRegex())
                val iface = parts[0]
                val isStandard = STANDARD_INTERFACES.any { it.matches(iface) }
                if (isStandard) {
                    findings.add(Finding("Маршрут по умолчанию: $iface (стандартный)"))
                    continue
                }

                findings.add(
                    Finding(
                        description = "Маршрут по умолчанию через нестандартный интерфейс: $iface",
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Default route points to non-standard interface $iface",
                    ),
                )
                detected = true
            }

            detected
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке маршрутов: ${e.message}"))
            false
        }
    }

    private fun checkDns(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            if (activeNetwork == null) {
                findings.add(Finding("DNS: активная сеть не найдена"))
                return SignalOutcome()
            }

            val linkProperties = cm.getLinkProperties(activeNetwork)
            if (linkProperties == null) {
                findings.add(Finding("DNS: LinkProperties недоступны"))
                return SignalOutcome()
            }

            val dnsServers = linkProperties.dnsServers
            if (dnsServers.isEmpty()) {
                findings.add(Finding("DNS серверы: не обнаружены"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (dns in dnsServers) {
                val addr = dns.hostAddress ?: continue
                when (classifyDnsAddress(addr)) {
                    DnsClassification.LOOPBACK -> {
                        findings.add(
                            Finding(
                                description = "DNS указывает на localhost: $addr (типично для VPN)",
                                detected = true,
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.HIGH,
                            ),
                        )
                        evidence.add(
                            EvidenceItem(
                                source = EvidenceSource.DNS,
                                detected = true,
                                confidence = EvidenceConfidence.HIGH,
                                description = "DNS resolver uses loopback address $addr",
                            ),
                        )
                        detected = true
                    }
                    DnsClassification.PRIVATE_LAN -> {
                        findings.add(Finding("DNS: $addr (локальный резолвер приватной сети)"))
                    }
                    DnsClassification.PRIVATE_TUNNEL -> {
                        findings.add(
                            Finding(
                                description = "DNS в частной подсети: $addr (может указывать на VPN-туннель)",
                                needsReview = true,
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.MEDIUM,
                            ),
                        )
                        evidence.add(
                            EvidenceItem(
                                source = EvidenceSource.DNS,
                                detected = true,
                                confidence = EvidenceConfidence.MEDIUM,
                                description = "DNS resolver uses private tunnel address $addr",
                            ),
                        )
                        needsReview = true
                    }
                    DnsClassification.KNOWN_PUBLIC_RESOLVER -> {
                        findings.add(
                            Finding(
                                description = "DNS использует публичный резолвер: $addr",
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.LOW,
                            ),
                        )
                    }
                    DnsClassification.LINK_LOCAL -> findings.add(Finding("DNS: $addr (link-local)"))
                    DnsClassification.OTHER_PUBLIC -> findings.add(Finding("DNS: $addr"))
                }
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке DNS: ${e.message}"))
            SignalOutcome()
        }
    }

    private fun checkDumpsysVpn(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SignalOutcome()
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding("dumpsys vpn_management: недоступен"))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnManagement(output)
            if (records.isEmpty()) {
                findings.add(Finding("dumpsys vpn_management: активных VPN нет"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val description = buildString {
                    append("VPN management: ")
                    append(record.rawLine)
                    signature?.family?.let {
                        append(" [")
                        append(it)
                        append("]")
                    }
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = record.rawLine,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = null,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("dumpsys vpn_management: ${e.message}"))
            SignalOutcome()
        }
    }

    private fun checkDumpsysVpnService(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding("dumpsys activity services VpnService: недоступен"))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnServices(output)
            if (records.isEmpty()) {
                findings.add(Finding("Активные VpnService: не обнаружены"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val serviceDisplay = if (record.packageName != null && record.serviceName != null) {
                    "${record.packageName}/${record.serviceName}"
                } else {
                    record.rawLine
                }
                val description = buildString {
                    append("VpnService активен: ")
                    append(serviceDisplay)
                    signature?.family?.let {
                        append(" [")
                        append(it)
                        append("]")
                    }
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = serviceDisplay,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = record.serviceName,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("dumpsys activity services: ${e.message}"))
            SignalOutcome()
        }
    }

    private fun isPrivate172(addr: String): Boolean {
        val parts = addr.split(".")
        if (parts.size < 2) return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 16..31
    }

    internal fun classifyDnsAddress(addr: String): DnsClassification {
        val normalized = addr.lowercase()
        if (normalized == "::1" || normalized.startsWith("127.")) return DnsClassification.LOOPBACK
        if (normalized.startsWith("169.254.") || normalized.startsWith("fe80:")) {
            return DnsClassification.LINK_LOCAL
        }
        if (
            normalized.startsWith("10.") ||
            (normalized.startsWith("172.") && isPrivate172(normalized)) ||
            normalized.startsWith("fc") ||
            normalized.startsWith("fd")
        ) {
            return DnsClassification.PRIVATE_TUNNEL
        }
        if (normalized.startsWith("192.168.")) return DnsClassification.PRIVATE_LAN
        if (normalized in KNOWN_PUBLIC_RESOLVERS) return DnsClassification.KNOWN_PUBLIC_RESOLVER
        return DnsClassification.OTHER_PUBLIC
    }

    internal fun classifyDnsSignalStatus(addr: String): DnsSignalStatus {
        return when (classifyDnsAddress(addr)) {
            DnsClassification.LOOPBACK -> DnsSignalStatus.DETECTED
            DnsClassification.PRIVATE_TUNNEL -> DnsSignalStatus.NEEDS_REVIEW
            DnsClassification.PRIVATE_LAN,
            DnsClassification.KNOWN_PUBLIC_RESOLVER,
            DnsClassification.LINK_LOCAL,
            DnsClassification.OTHER_PUBLIC,
            -> DnsSignalStatus.CLEAR
        }
    }
}
