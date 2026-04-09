package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.json.JSONObject

object GeoIpChecker {

    internal data class GeoIpSnapshot(
        val ip: String,
        val country: String,
        val countryCode: String,
        val isp: String,
        val org: String,
        val asn: String,
        val isProxy: Boolean,
        val isHosting: Boolean,
        val hostingVotes: Int,
        val hostingChecks: Int,
        val hostingSources: List<String>,
    )

    internal data class ProviderSnapshot(
        val provider: String,
        val snapshot: GeoIpSnapshot,
    )

    private const val IPAPI_PROVIDER = "ip-api.com"
    private const val IPAPIIS_PROVIDER = "ipapi.is"
    private const val IPLOCATE_PROVIDER = "iplocate.io"

    private const val IPAPI_URL =
        "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting,query"

    private const val IPAPIIS_URL = "https://api.ipapi.is/"

    private const val IPLOCATE_URL = "https://www.iplocate.io/api/lookup"

    suspend fun check(
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        try {
            coroutineScope {
                val ipApiDeferred = async { fetchIpApi(resolverConfig) }
                val ipapiIsDeferred = async { fetchIpapiIs(resolverConfig) }
                val iplocateDeferred = async { fetchIplocate(resolverConfig) }

                val ipApiResult = ipApiDeferred.await()
                val ipapiIsResult = ipapiIsDeferred.await()
                val iplocateResult = iplocateDeferred.await()

                val providers = listOfNotNull(ipApiResult, ipapiIsResult, iplocateResult)
                val baseProvider = ipApiResult ?: ipapiIsResult ?: iplocateResult
                    ?: return@coroutineScope errorResult("Ни один GeoIP-провайдер не вернул данные")

                evaluate(
                    mergeSnapshots(
                        baseProvider = baseProvider,
                        providers = providers,
                    ),
                )
            }
        } catch (e: Exception) {
            errorResult("Не удалось получить данные GeoIP: ${e.message}")
        }
    }

    private fun fetchIpApi(resolverConfig: DnsResolverConfig): ProviderSnapshot? {
        return try {
            val json = fetchJson(IPAPI_URL, resolverConfig)
            if (json.optString("status") != "success") return null

            ProviderSnapshot(
                provider = IPAPI_PROVIDER,
                snapshot = GeoIpSnapshot(
                    ip = firstMeaningful(json.optString("query"), default = "N/A"),
                    country = firstMeaningful(json.optString("country"), default = "N/A"),
                    countryCode = firstMeaningful(json.optString("countryCode"), default = ""),
                    isp = firstMeaningful(json.optString("isp"), default = "N/A"),
                    org = firstMeaningful(json.optString("org"), default = "N/A"),
                    asn = firstMeaningful(json.optString("as"), default = "N/A"),
                    isProxy = json.optBoolean("proxy", false),
                    isHosting = json.optBoolean("hosting", false),
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchIpapiIs(resolverConfig: DnsResolverConfig): ProviderSnapshot? {
        return try {
            val json = fetchJson(IPAPIIS_URL, resolverConfig)
            if (!json.has("ip")) return null

            val location = json.optJSONObject("location")
            val company = json.optJSONObject("company")
            val datacenter = json.optJSONObject("datacenter")
            val asn = json.optJSONObject("asn")

            ProviderSnapshot(
                provider = IPAPIIS_PROVIDER,
                snapshot = GeoIpSnapshot(
                    ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                    country = firstMeaningful(location?.optString("country"), default = "N/A"),
                    countryCode = firstMeaningful(location?.optString("country_code"), default = ""),
                    isp = firstMeaningful(
                        company?.optString("name"),
                        asn?.optString("org"),
                        datacenter?.optString("datacenter"),
                        asn?.optString("descr"),
                        default = "N/A",
                    ),
                    org = firstMeaningful(
                        datacenter?.optString("datacenter"),
                        company?.optString("name"),
                        asn?.optString("org"),
                        asn?.optString("descr"),
                        default = "N/A",
                    ),
                    asn = formatAsn(
                        code = asn?.opt("asn")?.toString(),
                        name = firstMeaningful(
                            asn?.optString("org"),
                            asn?.optString("descr"),
                            default = "N/A",
                        ),
                    ),
                    isProxy = json.optBoolean("is_proxy", false) ||
                        json.optBoolean("is_vpn", false) ||
                        json.optBoolean("is_tor", false),
                    isHosting = json.optBoolean("is_datacenter", false),
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchIplocate(resolverConfig: DnsResolverConfig): ProviderSnapshot? {
        return try {
            val json = fetchJson(IPLOCATE_URL, resolverConfig)
            if (!json.has("ip")) return null

            val privacy = json.optJSONObject("privacy")
            val company = json.optJSONObject("company")
            val hosting = json.optJSONObject("hosting")
            val asn = json.optJSONObject("asn")

            ProviderSnapshot(
                provider = IPLOCATE_PROVIDER,
                snapshot = GeoIpSnapshot(
                    ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                    country = firstMeaningful(json.optString("country"), default = "N/A"),
                    countryCode = firstMeaningful(json.optString("country_code"), default = ""),
                    isp = firstMeaningful(
                        company?.optString("name"),
                        asn?.optString("name"),
                        hosting?.optString("provider"),
                        default = "N/A",
                    ),
                    org = firstMeaningful(
                        hosting?.optString("provider"),
                        company?.optString("name"),
                        asn?.optString("name"),
                        default = "N/A",
                    ),
                    asn = formatAsn(
                        code = asn?.optString("asn"),
                        name = firstMeaningful(asn?.optString("name"), default = "N/A"),
                    ),
                    isProxy = (privacy?.optBoolean("is_proxy", false) == true) ||
                        (privacy?.optBoolean("is_vpn", false) == true) ||
                        (privacy?.optBoolean("is_tor", false) == true),
                    isHosting = privacy?.optBoolean("is_hosting", false) == true,
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchJson(url: String, resolverConfig: DnsResolverConfig): JSONObject {
        val response = ResolverNetworkStack.execute(
            url = url,
            method = "GET",
            timeoutMs = 10_000,
            config = resolverConfig,
        )
        if (response.code !in 200..299) {
            throw IllegalStateException("HTTP ${response.code}")
        }
        return JSONObject(response.body)
    }

    internal fun mergeSnapshots(
        baseProvider: ProviderSnapshot,
        providers: List<ProviderSnapshot>,
    ): GeoIpSnapshot {
        val compatibleProviders = providers.filter {
            isCompatibleIp(
                expectedIp = baseProvider.snapshot.ip,
                candidateIp = it.snapshot.ip,
            )
        }

        val orderedForFill = buildList {
            add(baseProvider)
            compatibleProviders
                .filterNot { it.provider == baseProvider.provider }
                .forEach(::add)
        }

        val hostingVotes = compatibleProviders.count { it.snapshot.isHosting }
        val hostingChecks = compatibleProviders.size
        val hostingSources = compatibleProviders
            .filter { it.snapshot.isHosting }
            .map { it.provider }

        return GeoIpSnapshot(
            ip = pickField(orderedForFill) { it.snapshot.ip },
            country = pickField(orderedForFill) { it.snapshot.country },
            countryCode = pickField(orderedForFill, default = "") { it.snapshot.countryCode },
            isp = pickField(orderedForFill) { it.snapshot.isp },
            org = pickField(orderedForFill) { it.snapshot.org },
            asn = pickField(orderedForFill) { it.snapshot.asn },
            isProxy = resolveProxy(
                baseProvider = baseProvider,
                compatibleProviders = compatibleProviders,
            ),
            isHosting = hostingVotes > hostingChecks / 2,
            hostingVotes = hostingVotes,
            hostingChecks = hostingChecks,
            hostingSources = hostingSources,
        )
    }

    internal fun evaluate(snapshot: GeoIpSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        findings.add(Finding("IP: ${snapshot.ip}", isInformational = true))
        findings.add(Finding("Страна: ${snapshot.country} (${snapshot.countryCode})", isInformational = true))
        findings.add(Finding("ISP: ${snapshot.isp}", isInformational = true))
        findings.add(Finding("Организация: ${snapshot.org}", isInformational = true))
        findings.add(Finding("ASN: ${snapshot.asn}", isInformational = true))

        val foreignIp = snapshot.countryCode.isNotEmpty() && snapshot.countryCode != "RU"
        val needsReview = foreignIp && !snapshot.isHosting && !snapshot.isProxy
        findings.add(
            Finding(
                description = "IP вне России: ${if (foreignIp) "да (${snapshot.countryCode})" else "нет"}",
                needsReview = needsReview,
                source = EvidenceSource.GEO_IP,
                confidence = needsReview.takeIf { it }?.let { EvidenceConfidence.LOW },
            ),
        )

        val hostingDesc = buildString {
            append("IP принадлежит хостинг-провайдеру: ${if (snapshot.isHosting) "да" else "нет"}")
            if (snapshot.hostingChecks > 0) {
                append(" (${snapshot.hostingVotes}/${snapshot.hostingChecks}")
                if (snapshot.hostingSources.isNotEmpty()) {
                    append(": ")
                    append(snapshot.hostingSources.joinToString(", "))
                }
                append(")")
            }
        }
        addGeoFinding(
            findings = findings,
            evidence = evidence,
            description = hostingDesc,
            detected = snapshot.isHosting,
        )
        addGeoFinding(
            findings = findings,
            evidence = evidence,
            description = "IP в базе известных прокси/VPN: ${if (snapshot.isProxy) "да" else "нет"}",
            detected = snapshot.isProxy,
        )

        return CategoryResult(
            name = "GeoIP",
            detected = snapshot.isHosting || snapshot.isProxy,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private fun errorResult(message: String): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding("Ошибка GeoIP: $message")),
        )
    }

    private fun addGeoFinding(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        description: String,
        detected: Boolean,
    ) {
        findings.add(
            Finding(
                description = description,
                detected = detected,
                source = EvidenceSource.GEO_IP,
                confidence = detected.takeIf { it }?.let { EvidenceConfidence.MEDIUM },
            ),
        )
        if (detected) {
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.GEO_IP,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = description,
                ),
            )
        }
    }

    private fun resolveProxy(
        baseProvider: ProviderSnapshot,
        compatibleProviders: List<ProviderSnapshot>,
    ): Boolean {
        if (baseProvider.provider == IPAPI_PROVIDER) {
            return baseProvider.snapshot.isProxy
        }
        return compatibleProviders.any { it.snapshot.isProxy }
    }

    private fun pickField(
        providers: List<ProviderSnapshot>,
        default: String = "N/A",
        selector: (ProviderSnapshot) -> String,
    ): String {
        return providers
            .asSequence()
            .map(selector)
            .firstOrNull(::isMeaningfulField)
            ?: default
    }

    private fun isCompatibleIp(expectedIp: String, candidateIp: String): Boolean {
        if (!isMeaningfulField(expectedIp) || !isMeaningfulField(candidateIp)) {
            return true
        }
        return expectedIp.equals(candidateIp, ignoreCase = true)
    }

    private fun formatAsn(code: String?, name: String?): String {
        val normalizedCode = code
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        val normalizedName = name
            ?.trim()
            ?.takeIf(::isMeaningfulField)

        if (normalizedCode == null) {
            return normalizedName ?: "N/A"
        }

        val asnCode = if (normalizedCode.startsWith("AS", ignoreCase = true)) {
            normalizedCode.uppercase()
        } else {
            "AS$normalizedCode"
        }
        return normalizedName?.let { "$asnCode $it" } ?: asnCode
    }

    private fun firstMeaningful(vararg candidates: String?, default: String): String {
        return candidates.firstOrNull(::isMeaningfulField)?.trim() ?: default
    }

    private fun isMeaningfulField(value: String?): Boolean {
        return !value.isNullOrBlank() && !value.equals("N/A", ignoreCase = true)
    }
}
