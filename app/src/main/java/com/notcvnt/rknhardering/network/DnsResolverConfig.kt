package com.notcvnt.rknhardering.network

import android.content.SharedPreferences
import java.net.URL
import java.util.Locale

enum class DnsResolverMode(val prefValue: String) {
    SYSTEM("system"),
    DIRECT("direct"),
    DOH("doh");

    companion object {
        fun fromPref(value: String?): DnsResolverMode {
            return entries.firstOrNull { it.prefValue == value } ?: SYSTEM
        }
    }
}

enum class DnsResolverPreset(val prefValue: String) {
    CUSTOM("custom"),
    CLOUDFLARE("cloudflare"),
    GOOGLE("google"),
    YANDEX("yandex");

    companion object {
        fun fromPref(value: String?): DnsResolverPreset {
            return entries.firstOrNull { it.prefValue == value } ?: CUSTOM
        }
    }
}

data class DnsResolverPresetSpec(
    val directServers: List<String>,
    val dohUrl: String,
    val dohBootstrapHosts: List<String>,
)

object DnsResolverPresets {
    private val presetSpecs = mapOf(
        DnsResolverPreset.CLOUDFLARE to DnsResolverPresetSpec(
            directServers = listOf("1.1.1.1", "1.0.0.1"),
            dohUrl = "https://cloudflare-dns.com/dns-query",
            dohBootstrapHosts = listOf("1.1.1.1", "1.0.0.1"),
        ),
        DnsResolverPreset.GOOGLE to DnsResolverPresetSpec(
            directServers = listOf("8.8.8.8", "8.8.4.4"),
            dohUrl = "https://dns.google/dns-query",
            dohBootstrapHosts = listOf("8.8.8.8", "8.8.4.4"),
        ),
        DnsResolverPreset.YANDEX to DnsResolverPresetSpec(
            directServers = listOf("77.88.8.8", "77.88.8.1"),
            dohUrl = "https://common.dot.dns.yandex.net/dns-query",
            dohBootstrapHosts = listOf("77.88.8.8", "77.88.8.1"),
        ),
    )

    fun spec(preset: DnsResolverPreset): DnsResolverPresetSpec? = presetSpecs[preset]
}

data class DnsResolverConfig(
    val mode: DnsResolverMode = DnsResolverMode.SYSTEM,
    val preset: DnsResolverPreset = DnsResolverPreset.CUSTOM,
    val customDirectServers: List<String> = emptyList(),
    val customDohUrl: String? = null,
    val customDohBootstrapHosts: List<String> = emptyList(),
) {
    fun effectiveDirectServers(): List<String> {
        if (mode != DnsResolverMode.DIRECT) return emptyList()
        return effectivePresetSpec()?.directServers ?: customDirectServers
    }

    fun effectiveDohUrl(): String? {
        if (mode != DnsResolverMode.DOH) return null
        return effectivePresetSpec()?.dohUrl ?: customDohUrl?.trim().takeUnless { it.isNullOrEmpty() }
    }

    fun effectiveDohBootstrapHosts(): List<String> {
        if (mode != DnsResolverMode.DOH) return emptyList()
        return (effectivePresetSpec()?.dohBootstrapHosts ?: customDohBootstrapHosts)
            .distinct()
    }

    fun sanitized(): DnsResolverConfig {
        return when (mode) {
            DnsResolverMode.SYSTEM -> system()
            DnsResolverMode.DIRECT -> {
                if (effectiveDirectServers().isEmpty()) system() else this
            }
            DnsResolverMode.DOH -> {
                val url = effectiveDohUrl()
                if (url.isNullOrBlank() || !isValidDohUrl(url)) system() else this
            }
        }
    }

    private fun effectivePresetSpec(): DnsResolverPresetSpec? {
        if (preset == DnsResolverPreset.CUSTOM) return null
        return DnsResolverPresets.spec(preset)
    }

    companion object {
        fun system(): DnsResolverConfig = DnsResolverConfig()

        fun fromPrefs(
            prefs: SharedPreferences,
            modePref: String,
            presetPref: String,
            directServersPref: String,
            dohUrlPref: String,
            dohBootstrapPref: String,
        ): DnsResolverConfig {
            return DnsResolverConfig(
                mode = DnsResolverMode.fromPref(prefs.getString(modePref, DnsResolverMode.SYSTEM.prefValue)),
                preset = DnsResolverPreset.fromPref(prefs.getString(presetPref, DnsResolverPreset.CUSTOM.prefValue)),
                customDirectServers = parseAddressList(prefs.getString(directServersPref, "")),
                customDohUrl = prefs.getString(dohUrlPref, "")?.trim().takeUnless { it.isNullOrEmpty() },
                customDohBootstrapHosts = parseAddressList(prefs.getString(dohBootstrapPref, "")),
            ).sanitized()
        }

        fun parseAddressList(raw: String?): List<String> {
            return raw
                .orEmpty()
                .split(Regex("[,;\\s]+"))
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
        }

        fun serializeAddressList(values: List<String>): String = values.joinToString(", ")

        fun isValidIpLiteral(value: String): Boolean {
            val normalized = value.trim()
            if (normalized.isEmpty()) return false
            if (normalized.contains("://")) return false
            val ipv4 = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
            val ipv6 = Regex("""^[0-9a-fA-F:]+$""")
            return ipv4.matches(normalized) || ipv6.matches(normalized)
        }

        fun isValidDohUrl(value: String): Boolean {
            return runCatching {
                val url = URL(value.trim())
                url.protocol.lowercase(Locale.US) == "https" && !url.host.isNullOrBlank()
            }.getOrDefault(false)
        }
    }
}
