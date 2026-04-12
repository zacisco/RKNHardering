package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Detects whether a non-VPN (underlying) network is reachable from this app.
 *
 * When VPN runs in split-tunnel / per-app mode, apps excluded from the tunnel
 * (or any app that can bind to the underlying network) can reach the VPN gateway
 * and any external host directly, leaking the real IP and confirming VPN usage.
 *
 * The probe enumerates all networks, finds one without TRANSPORT_VPN, binds an
 * HTTPS request to it, and fetches the public IP. Success means split-tunnel
 * vulnerability is present.
 */
object UnderlyingNetworkProber {

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean,
        val vpnIp: String? = null,
        val underlyingIp: String? = null,
        val vpnError: String? = null,
        val underlyingError: String? = null,
        val vpnNetwork: Network? = null,
        val underlyingNetwork: Network? = null,
        val activeNetworkIsVpn: Boolean? = null,
    )

    private data class IpEndpoint(
        val url: String,
        val ruBased: Boolean,
    )

    private val IP_ENDPOINTS = listOf(
        IpEndpoint("https://ifconfig.me/ip", ruBased = false),
        IpEndpoint("https://checkip.amazonaws.com", ruBased = false),
        IpEndpoint("https://ipv4-internet.yandex.net/api/v0/ip", ruBased = true),
        IpEndpoint("https://ipv6-internet.yandex.net/api/v0/ip", ruBased = true),
    )

    private const val TIMEOUT_MS = 7000

    @Suppress("DEPRECATION")
    suspend fun probe(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): ProbeResult = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val activeNetworkIsVpn = activeNetwork
            ?.let(cm::getNetworkCapabilities)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        val allNetworks = cm.allNetworks
        var vpnNetwork: Network? = null
        val nonVpnNetworks = mutableListOf<Network>()

        for (network in allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = network
            } else {
                nonVpnNetworks.add(network)
            }
        }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(
                vpnActive = false,
                underlyingReachable = false,
                activeNetworkIsVpn = activeNetworkIsVpn,
            )
        }

        val vpnResult = fetchIpViaNetwork(vpnNetwork, resolverConfig)
        val vpnIp = vpnResult.getOrNull()
        val vpnError = vpnResult.exceptionOrNull()?.message

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = vpnIp,
                vpnError = vpnError,
                vpnNetwork = vpnNetwork,
                activeNetworkIsVpn = activeNetworkIsVpn,
            )
        }

        var underlyingIp: String? = null
        var underlyingError: String? = null
        var usedNetwork: Network? = null

        for (network in nonVpnNetworks) {
            val result = fetchIpViaNetwork(network, resolverConfig)
            underlyingIp = result.getOrNull()
            if (underlyingIp != null) {
                usedNetwork = network
                underlyingError = null
                break
            }
            underlyingError = result.exceptionOrNull()?.message ?: underlyingError
        }

        ProbeResult(
            vpnActive = true,
            underlyingReachable = underlyingIp != null,
            vpnIp = vpnIp,
            underlyingIp = underlyingIp,
            vpnError = vpnError,
            underlyingError = underlyingError,
            vpnNetwork = vpnNetwork,
            underlyingNetwork = usedNetwork,
            activeNetworkIsVpn = activeNetworkIsVpn,
        )
    }

    private fun fetchIpViaNetwork(
        network: Network,
        resolverConfig: DnsResolverConfig,
    ): Result<String> {
        var lastError: Exception? = null
        for (endpoint in IP_ENDPOINTS) {
            val result = PublicIpClient.fetchIp(
                endpoint = endpoint.url,
                timeoutMs = TIMEOUT_MS,
                resolverConfig = resolverConfig,
                network = network,
            )
            if (result.isSuccess) return result
            lastError = result.exceptionOrNull() as? Exception ?: lastError
        }
        return Result.failure(lastError ?: IOException("All IP endpoints failed"))
    }
}
