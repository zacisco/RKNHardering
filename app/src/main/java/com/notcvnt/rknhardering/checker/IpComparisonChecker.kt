package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.PublicIpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URL

object IpComparisonChecker {

    private enum class IpFamily {
        IPV4,
        IPV6,
    }

    private data class EndpointSpec(
        val label: String,
        val url: String,
        val scope: IpCheckerScope,
    )

    private val ENDPOINTS = listOf(
        EndpointSpec(
            label = "Yandex IPv4",
            url = "https://ipv4-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "2ip.ru",
            url = "https://2ip.ru",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "Yandex IPv6",
            url = "https://ipv6-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "ifconfig.me IPv4",
            url = "https://ipv4.ifconfig.me/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ifconfig.me IPv6",
            url = "https://ipv6.ifconfig.me/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "checkip.amazonaws.com",
            url = "https://checkip.amazonaws.com",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ipify",
            url = "https://api.ipify.org",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ip.sb IPv4",
            url = "https://api-ipv4.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ip.sb IPv6",
            url = "https://api-ipv6.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
        ),
    )

    suspend fun check(
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): IpComparisonResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val responses = ENDPOINTS.map { endpoint ->
                async {
                    val dnsRecords = PublicIpClient.resolveDnsRecords(endpoint.url, resolverConfig)
                    val result = PublicIpClient.fetchIp(endpoint.url, timeoutMs, resolverConfig = resolverConfig)
                    val error = result.exceptionOrNull()?.let(::formatError)
                    IpCheckerResponse(
                        label = endpoint.label,
                        url = endpoint.url,
                        scope = endpoint.scope,
                        ip = result.getOrNull(),
                        error = error,
                        ipv4Records = dnsRecords.ipv4Records,
                        ipv6Records = dnsRecords.ipv6Records,
                        ignoredIpv6Error = shouldIgnoreIpv6Error(
                            url = endpoint.url,
                            error = error,
                            dnsRecords = dnsRecords,
                        ),
                    )
                }
            }.map { it.await() }
            evaluate(responses)
        }
    }

    internal fun evaluate(responses: List<IpCheckerResponse>): IpComparisonResult {
        val ruGroup = buildGroup(
            title = "RU-чекеры",
            responses = responses.filter { it.scope == IpCheckerScope.RU },
        )
        val nonRuGroup = buildGroup(
            title = "Не-RU чекеры",
            responses = responses.filter { it.scope == IpCheckerScope.NON_RU },
        )

        val fullConsensusAvailable = !ruGroup.needsReview &&
            !nonRuGroup.needsReview &&
            !ruGroup.detected &&
            !nonRuGroup.detected &&
            ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null

        val familyMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            detectFamily(ruGroup.canonicalIp) != detectFamily(nonRuGroup.canonicalIp)

        val rawMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            !familyMismatch &&
            ruGroup.canonicalIp != nonRuGroup.canonicalIp

        val detected = fullConsensusAvailable && rawMismatch
        val needsReview = !detected && (
            ruGroup.detected ||
                nonRuGroup.detected ||
                ruGroup.needsReview ||
                nonRuGroup.needsReview ||
                familyMismatch ||
                rawMismatch
            )

        val summary = when {
            detected -> "RU и не-RU чекеры вернули разные IP: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            familyMismatch -> "RU и не-RU чекеры вернули адреса разных семейств: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            rawMismatch -> "IP различаются, но данные неполные: ${ruGroup.canonicalIp} и ${nonRuGroup.canonicalIp}"
            ruGroup.ignoredIpv6ErrorCount > 0 || nonRuGroup.ignoredIpv6ErrorCount > 0 ->
                "Все ответившие IPv4-чекеры вернули один IP: ${ruGroup.canonicalIp ?: nonRuGroup.canonicalIp}"
            ruGroup.canonicalIp != null && nonRuGroup.canonicalIp != null ->
                "Все чекеры вернули один IP: ${ruGroup.canonicalIp}"
            ruGroup.canonicalIp == null && nonRuGroup.canonicalIp == null ->
                "Не удалось получить ответ ни от одного IP-чекера"
            else -> "Сравнение неполное: часть чекеров не ответила"
        }

        return IpComparisonResult(
            detected = detected,
            needsReview = needsReview,
            summary = summary,
            ruGroup = ruGroup,
            nonRuGroup = nonRuGroup,
        )
    }

    private fun buildGroup(
        title: String,
        responses: List<IpCheckerResponse>,
    ): IpCheckerGroupResult {
        if (responses.size == 1) {
            val response = responses.single()
            return if (response.ip != null) {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = false,
                    statusLabel = "Есть ответ",
                    summary = "IP: ${response.ip}",
                    canonicalIp = response.ip,
                    responses = responses,
                )
            } else {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = true,
                    statusLabel = "Нет ответа",
                    summary = response.error?.let { "Ошибка: $it" } ?: "Сервис не ответил",
                    responses = responses,
                )
            }
        }

        val successfulIps = responses.mapNotNull { it.ip }
        val uniqueIps = successfulIps.distinct()
        val failureCount = responses.count { it.ip == null && !it.ignoredIpv6Error }
        val ignoredIpv6ErrorCount = responses.count { it.ip == null && it.ignoredIpv6Error }
        val families = successfulIps.mapNotNull(::detectFamily).distinct()

        return when {
            uniqueIps.isEmpty() && failureCount > 0 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "Нет ответа",
                summary = "Ни один сервис не вернул IP",
                responses = responses,
            )
            uniqueIps.isEmpty() -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = false,
                statusLabel = "IPv6 игнор",
                summary = "IPv6-ошибки проигнорированы, валидного IPv4-ответа нет",
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            families.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "IPv4/IPv6",
                summary = "Сервисы вернули адреса разных семейств: ${uniqueIps.joinToString()}",
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            uniqueIps.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = true,
                needsReview = false,
                statusLabel = "Разнобой",
                summary = "Сервисы вернули разные IP: ${uniqueIps.joinToString()}",
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            failureCount > 0 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = "Частично",
                summary = "IP ${uniqueIps.single()}, но ${failureCount} из ${responses.size} сервисов не ответили",
                canonicalIp = uniqueIps.single(),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            else -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = false,
                statusLabel = "Совпадает",
                summary = buildString {
                    append("Все ответившие сервисы группы вернули IP ${uniqueIps.single()}")
                    if (ignoredIpv6ErrorCount > 0) {
                        append("; IPv6-ошибки проигнорированы: ")
                        append(ignoredIpv6ErrorCount)
                    }
                },
                canonicalIp = uniqueIps.single(),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
        }
    }

    private fun formatError(throwable: Throwable): String {
        val message = throwable.message?.trim().orEmpty()
        if (message.isNotBlank()) return message
        return when (throwable) {
            is IOException -> "Сетевая ошибка"
            else -> throwable::class.java.simpleName
        }
    }

    private fun detectFamily(ip: String?): IpFamily? {
        return when {
            ip == null -> null
            ip.contains(':') -> IpFamily.IPV6
            ip.contains('.') -> IpFamily.IPV4
            else -> null
        }
    }

    private fun shouldIgnoreIpv6Error(
        url: String,
        error: String?,
        dnsRecords: PublicIpClient.DnsRecords,
    ): Boolean {
        if (error.isNullOrBlank()) return false
        val host = try {
            URL(url).host.lowercase()
        } catch (_: Exception) {
            ""
        }
        if (host.contains("ipv6")) {
            return true
        }
        val normalizedError = error.lowercase()
        if (Regex("""\[[0-9a-f:]+]""").containsMatchIn(normalizedError)) {
            return true
        }
        if (normalizedError.contains("address family not supported")) {
            return true
        }
        if (normalizedError.contains("network is unreachable") && dnsRecords.ipv6Records.isNotEmpty()) {
            return true
        }
        if (normalizedError.contains("no route to host") && dnsRecords.ipv6Records.isNotEmpty()) {
            return true
        }
        return false
    }
}
