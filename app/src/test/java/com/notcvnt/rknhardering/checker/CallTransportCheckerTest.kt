package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.PublicIpClient
import com.notcvnt.rknhardering.probe.Socks5UdpAssociateClient
import com.notcvnt.rknhardering.probe.StunBindingClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class CallTransportCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        CallTransportChecker.dependenciesOverride = null
        PublicIpClient.resetForTests()
    }

    @Test
    fun `probeDirect keeps active path as baseline signal`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                    ),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NO_SIGNAL, telegram.status)
        assertEquals(CallTransportProbeKind.DIRECT_UDP_STUN, telegram.probeKind)
        assertEquals(CallTransportNetworkPath.ACTIVE, telegram.networkPath)
        assertEquals("149.154.167.51", telegram.targetHost)
        assertEquals("198.51.100.20", telegram.mappedIp)
        assertEquals("203.0.113.10", telegram.observedPublicIp)
    }

    @Test
    fun `probeDirect flags active vpn path when stun ip diverges from public ip`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                        vpnProtected = true,
                    ),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
    }

    @Test
    fun `probeDirect flags explicit underlying path for review`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                    ),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
            publicIpFetcher = { _, _ -> Result.success("198.51.100.20") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        assertEquals(CallTransportNetworkPath.UNDERLYING, telegram.networkPath)
    }

    @Test
    fun `probeDirect converts no response into no signal`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                    ),
                )
            },
            stunProbe = { _, _, _ -> Result.failure(IllegalStateException("timeout")) },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        assertTrue(results.any { it.service == CallTransportService.TELEGRAM && it.status == CallTransportStatus.NO_SIGNAL })
        assertTrue(results.any { it.service == CallTransportService.WHATSAPP && it.status == CallTransportStatus.UNSUPPORTED })
        assertFalse(results.any { it.service == CallTransportService.TELEGRAM && it.status == CallTransportStatus.ERROR })
    }

    @Test
    fun `probeDirect reports unsupported when telegram catalog is empty`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = emptyList(),
                    whatsappTargets = emptyList(),
                )
            },
        )

        val results = runBlockingProbeDirect(experimental = false)

        assertTrue(results.any { it.service == CallTransportService.TELEGRAM && it.status == CallTransportStatus.UNSUPPORTED })
    }

    @Test
    fun `proxy assisted telegram stores remote dc as target not local proxy`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = emptyList(),
                    whatsappTargets = emptyList(),
                )
            },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(
                    reachable = true,
                    targetHost = "149.154.167.51",
                    targetPort = 443,
                    observedPublicIp = "203.0.113.10",
                )
            },
        )

        val result = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        val tcpResult = result.first { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, tcpResult.status)
        assertEquals("149.154.167.51", tcpResult.targetHost)
        assertEquals(443, tcpResult.targetPort)
        assertNull(tcpResult.mappedIp)
        assertEquals("203.0.113.10", tcpResult.observedPublicIp)
    }

    @Test
    fun `proxy assisted telegram adds udp stun signal when udp associate succeeds`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, _ -> Result.success("203.0.113.10") }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ -> successBindingResult() },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        val udpResult = results.first { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN }
        assertEquals(CallTransportNetworkPath.LOCAL_PROXY, udpResult.networkPath)
        assertEquals(CallTransportStatus.NEEDS_REVIEW, udpResult.status)
        assertEquals("149.154.167.51", udpResult.targetHost)
        assertEquals("198.51.100.20", udpResult.mappedIp)
        assertEquals("203.0.113.10", udpResult.observedPublicIp)
    }

    @Test
    fun `proxy assisted telegram auth failures stay as no signal`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ ->
                Result.failure(Socks5UdpAssociateClient.AuthenticationRequiredException())
            },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        assertTrue(results.all { it.status == CallTransportStatus.NO_SIGNAL })
        assertFalse(results.any { it.status == CallTransportStatus.NEEDS_REVIEW })
    }

    @Test
    fun `check can discover proxy assisted path without bypass ownership`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, _ -> Result.success("203.0.113.10") }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = { emptyList() },
            findLocalProxyEndpoint = {
                ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5)
            },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ -> successBindingResult() },
        )

        val evaluation = kotlinx.coroutines.runBlocking {
            CallTransportChecker.check(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
                callTransportEnabled = true,
                experimentalCallTransportEnabled = false,
            )
        }

        assertTrue(evaluation.results.any { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN })
        assertTrue(evaluation.needsReview)
    }

    @Test
    fun `reusable udp relay candidates are derived from the same proxy owner`() {
        val owner = LocalProxyOwner(
            uid = 10123,
            packageNames = listOf("com.example.proxy"),
            appLabels = listOf("Proxy"),
            confidence = EvidenceConfidence.HIGH,
        )

        val candidates = CallTransportChecker.findReusableProxyUdpRelays(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            listeners = listOf(
                listener(protocol = "tcp", host = "127.0.0.1", port = 1080, owner = owner),
                listener(protocol = "udp", host = "0.0.0.0", port = 53000, owner = owner),
                listener(protocol = "udp6", host = "::", port = 53001, owner = owner),
                listener(
                    protocol = "udp",
                    host = "127.0.0.1",
                    port = 53002,
                    owner = owner.copy(uid = 10124),
                ),
            ),
        )

        assertEquals(
            setOf(
                Socks5UdpAssociateClient.SessionInfo(relayHost = "127.0.0.1", relayPort = 53000),
                Socks5UdpAssociateClient.SessionInfo(relayHost = "127.0.0.1", relayPort = 53001),
            ),
            candidates.toSet(),
        )
    }

    @Test
    fun `underlying path uses interface name for public ip fallback`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.10")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                        network = newNetwork(101),
                        interfaceName = "tun0",
                    ),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        assertTrue(observedBindings.any { it is ResolverBinding.AndroidNetworkBinding })
        val fallbackBinding = observedBindings.last { it is ResolverBinding.OsDeviceBinding } as ResolverBinding.OsDeviceBinding
        assertEquals("tun0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    @Test
    fun `underlying path normalizes stacked clat interface for public ip fallback`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.10")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                        network = newNetwork(101),
                        interfaceName = "v4-wlan0",
                    ),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        val fallbackBinding = observedBindings.last { it is ResolverBinding.OsDeviceBinding } as ResolverBinding.OsDeviceBinding
        assertEquals("wlan0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    @Test
    fun `underlying path retries stun probe with device binding fallback`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                        network = newNetwork(101),
                        interfaceName = "wlan0",
                    ),
                )
            },
            stunProbe = { _, _, binding ->
                observedBindings += binding
                when (binding) {
                    is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                    is ResolverBinding.OsDeviceBinding -> successBindingResult()
                    null -> Result.failure(IOException("unexpected unbound path"))
                }
            },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        assertTrue(observedBindings.any { it is ResolverBinding.AndroidNetworkBinding })
        val fallbackBinding = observedBindings.last { it is ResolverBinding.OsDeviceBinding } as ResolverBinding.OsDeviceBinding
        assertEquals("wlan0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    @Test
    fun `probeDirect probes all provided underlying paths`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { _, _ -> catalogWithTelegramTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.ACTIVE),
                    CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.UNDERLYING, interfaceName = "wlan0"),
                    CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.UNDERLYING, interfaceName = "rmnet0"),
                )
            },
            stunProbe = { _, _, _ -> successBindingResult() },
            publicIpFetcher = { path, _ ->
                val ip = when (path.interfaceName) {
                    "wlan0" -> "203.0.113.10"
                    "rmnet0" -> "203.0.113.11"
                    else -> "203.0.113.12"
                }
                Result.success(ip)
            },
        )

        val results = runBlockingProbeDirect(experimental = false)

        assertEquals(2, results.count { it.service == CallTransportService.TELEGRAM && it.networkPath == CallTransportNetworkPath.UNDERLYING })
    }

    private fun runBlockingProbeDirect(
        experimental: Boolean,
    ): List<CallTransportLeakResult> = kotlinx.coroutines.runBlocking {
        CallTransportChecker.probeDirect(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
            experimentalCallTransportEnabled = experimental,
        )
    }

    private fun successBindingResult(): Result<StunBindingClient.BindingResult> {
        return Result.success(
            StunBindingClient.BindingResult(
                resolvedIps = listOf("149.154.167.51"),
                remoteIp = "149.154.167.51",
                remotePort = 3478,
                mappedIp = "198.51.100.20",
                mappedPort = 40000,
            ),
        )
    }

    private fun catalogWithTelegramTarget(): CallTransportTargetCatalog.Catalog {
        return CallTransportTargetCatalog.Catalog(
            telegramTargets = listOf(
                CallTransportTargetCatalog.CallTransportTarget(
                    service = CallTransportService.TELEGRAM,
                    host = "149.154.167.51",
                    port = 3478,
                    experimental = false,
                    enabled = true,
                ),
            ),
            whatsappTargets = emptyList(),
        )
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }

    private fun listener(
        protocol: String,
        host: String,
        port: Int,
        owner: LocalProxyOwner,
    ): LocalSocketListener = LocalSocketListener(
        protocol = protocol,
        host = host,
        port = port,
        state = if (protocol.startsWith("tcp")) "0A" else "07",
        uid = owner.uid,
        inode = 0L,
        owner = owner,
    )
}
