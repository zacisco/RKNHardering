package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Proxy

object PublicIpClient {

    data class DnsRecords(
        val ipv4Records: List<String> = emptyList(),
        val ipv6Records: List<String> = emptyList(),
    )

    private const val USER_AGENT = "curl/8.0"
    private val HTML_TAG_REGEX = Regex("""<\s*(?:!doctype|html|head|body)\b""", RegexOption.IGNORE_CASE)

    fun fetchIp(
        endpoint: String,
        timeoutMs: Int = 7000,
        proxy: Proxy? = null,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> {
        return try {
            val response = ResolverNetworkStack.execute(
                url = endpoint,
                method = "GET",
                headers = mapOf(
                    "User-Agent" to USER_AGENT,
                    "Accept" to "text/plain",
                ),
                timeoutMs = timeoutMs,
                config = resolverConfig,
                proxy = proxy,
            )
            val code = response.code
            if (code !in 200..299) {
                return Result.failure(
                    IOException(formatHttpError(code, response.body)),
                )
            }

            val body = response.body.trim()
            if (body.isBlank()) {
                return Result.failure(IOException("Empty response body"))
            }
            val ip = extractIp(body)
                ?: return Result.failure(IOException("Response does not look like an IP: $body"))
            if (!looksLikeIp(ip)) {
                return Result.failure(IOException("Response does not look like an IP: $ip"))
            }
            Result.success(ip)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    internal fun extractIp(body: String): String? {
        val candidate = body
            .trim()
            .lineSequence()
            .map { it.trim() }
            .firstOrNull()
            ?.removeSurrounding("\"")
            ?.trim()
            .orEmpty()
        if (candidate.isBlank()) return null
        return candidate.takeIf(::looksLikeIp)
    }

    internal fun formatHttpError(code: Int, body: String): String {
        httpStatusLabel(code)?.let { label ->
            return "HTTP $code // $label"
        }

        val trimmedBody = body.trim()
        if (trimmedBody.isBlank() || looksLikeHtml(trimmedBody)) {
            return "HTTP $code"
        }

        val firstLine = trimmedBody
            .lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
            .orEmpty()

        if (firstLine.isBlank() || firstLine.length > 160) {
            return "HTTP $code"
        }

        return "HTTP $code: $firstLine"
    }

    fun resolveDnsRecords(
        endpoint: String,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): DnsRecords {
        return try {
            val host = java.net.URL(endpoint).host
            val allAddresses = ResolverNetworkStack.lookup(host, resolverConfig)
            DnsRecords(
                ipv4Records = allAddresses
                    .filterIsInstance<Inet4Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
                ipv6Records = allAddresses
                    .filterIsInstance<Inet6Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
            )
        } catch (_: Exception) {
            DnsRecords()
        }
    }

    private fun looksLikeIp(text: String): Boolean {
        if (text.length > 45) return false
        return text.matches(Regex("""[\d.:a-fA-F]+"""))
    }

    private fun httpStatusLabel(code: Int): String? {
        return when (code) {
            403 -> "Запрещено"
            else -> null
        }
    }

    private fun looksLikeHtml(body: String): Boolean {
        return HTML_TAG_REGEX.containsMatchIn(body)
    }
}
