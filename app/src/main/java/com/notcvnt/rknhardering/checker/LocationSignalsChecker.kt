package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.Geocoder
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import androidx.annotation.DoNotInline
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.Locale

object LocationSignalsChecker {

    data class SimCardInfo(
        val slotIndex: Int,
        val subscriptionId: Int,
        val simMcc: String?,
        val simCountryIso: String?,
        val operatorName: String?,
        val isRoaming: Boolean?,
    )

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simCards: List<SimCardInfo>,
        val cellCountryCode: String?,
        val cellLookupSummary: String?,
        val cellCandidatesCount: Int,
        val wifiAccessPointCandidatesCount: Int,
        val bssid: String?,
        val cellLookupPermissionGranted: Boolean,
        val wifiPermissionGranted: Boolean,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"
    private const val CELL_INFO_TIMEOUT_MS = 3_000L
    private const val WIFI_SCAN_TIMEOUT_MS = 3_000L
    private const val MAX_CELL_TOWERS = 6
    private const val MAX_WIFI_ACCESS_POINTS = 12

    suspend fun check(
        context: Context,
        networkRequestsEnabled: Boolean = true,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        evaluate(collectSnapshot(context, networkRequestsEnabled, resolverConfig))
    }

    private suspend fun collectSnapshot(
        context: Context,
        networkRequestsEnabled: Boolean,
        resolverConfig: DnsResolverConfig,
    ): LocationSnapshot {
        val fineLocationGranted = hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        val nearbyWifiGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            hasPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            true
        }
        val cellLookupPermissionGranted = fineLocationGranted
        val wifiPermissionGranted = fineLocationGranted && nearbyWifiGranted

        var networkMcc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var cellCountryCode: String? = null
        var cellLookupSummary: String? = null
        var cellCandidatesCount = 0
        var wifiAccessPointCandidatesCount = 0

        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            val networkOperator = tm.networkOperator
            if (!networkOperator.isNullOrEmpty() && networkOperator.length >= 3) {
                networkMcc = networkOperator.substring(0, 3)
            }
            networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
            networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }
        }

        val simCards = collectSimCards(context, tm)

        val cellCandidates = if (cellLookupPermissionGranted) {
            collectCellCandidates(context, tm).also { cellCandidatesCount = it.size }
        } else {
            emptyList()
        }
        val wifiCandidates = if (wifiPermissionGranted) {
            collectWifiCandidates(context).also { wifiAccessPointCandidatesCount = it.size }
        } else {
            emptyList()
        }

        if ((cellLookupPermissionGranted || wifiPermissionGranted) && networkRequestsEnabled) {
            val lookup = BeaconDbClient(countryResolver = { lat, lon ->
                reverseGeocodeCountry(context, lat, lon)
            }, resolverConfig = resolverConfig).lookup(cellCandidates, wifiCandidates)
            cellCountryCode = lookup.countryCode
            cellLookupSummary = buildString {
                append(lookup.summary)
                if (lookup.latitude != null && lookup.longitude != null) {
                    append(" (${lookup.latitude}, ${lookup.longitude})")
                }
            }
        }

        val bssid = if (wifiPermissionGranted) {
            runCatching { getBssid(context) }.getOrNull()
        } else {
            null
        }

        return LocationSnapshot(
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

    private fun hasPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun collectSimCards(context: Context, tm: TelephonyManager): List<SimCardInfo> {
        val subscriptions = if (hasPermission(context, Manifest.permission.READ_PHONE_STATE)) {
            getActiveSubscriptions(context)
        } else {
            null
        }

        if (!subscriptions.isNullOrEmpty()) {
            return subscriptions.mapNotNull { info ->
                runCatching {
                    val subTm = tm.createForSubscriptionId(info.subscriptionId)
                    val simOperator = subTm.simOperator
                    val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                        simOperator.substring(0, 3)
                    } else null
                    SimCardInfo(
                        slotIndex = info.simSlotIndex,
                        subscriptionId = info.subscriptionId,
                        simMcc = simMcc,
                        simCountryIso = subTm.simCountryIso?.takeIf { it.isNotEmpty() },
                        operatorName = subTm.networkOperatorName?.takeIf { it.isNotEmpty() },
                        isRoaming = subTm.isNetworkRoaming,
                    )
                }.getOrNull()
            }
        }

        // Fallback: single-SIM device or permission denied
        return runCatching {
            val simOperator = tm.simOperator
            val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                simOperator.substring(0, 3)
            } else null
            listOf(
                SimCardInfo(
                    slotIndex = 0,
                    subscriptionId = -1,
                    simMcc = simMcc,
                    simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() },
                    operatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() },
                    isRoaming = tm.isNetworkRoaming,
                )
            )
        }.getOrElse { emptyList() }
    }

    @Suppress("MissingPermission")
    private fun getActiveSubscriptions(context: Context): List<android.telephony.SubscriptionInfo>? {
        val subscriptionManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                as? android.telephony.SubscriptionManager
        return runCatching { subscriptionManager?.activeSubscriptionInfoList }.getOrNull()
    }

    private suspend fun collectCellCandidates(
        context: Context,
        tm: TelephonyManager,
    ): List<CellLookupCandidate> {
        if (!hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)) {
            return emptyList()
        }
        val fresh = requestFreshCellInfo(context, tm)
        val fallback = getCachedCellInfo(tm)
        return (fresh.ifEmpty { fallback })
            .mapNotNull(::toLookupCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId) }
            .sortedWith(
                compareByDescending<CellLookupCandidate> { it.registered }
                    .thenByDescending { it.signalStrength ?: Int.MIN_VALUE },
            )
            .take(MAX_CELL_TOWERS)
    }

    @Suppress("MissingPermission")
    private suspend fun requestFreshCellInfo(
        context: Context,
        tm: TelephonyManager,
    ): List<CellInfo> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return emptyList()
        }

        return withTimeoutOrNull(CELL_INFO_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val completed = AtomicBoolean(false)
                val requested = runCatching {
                    tm.requestCellInfoUpdate(
                        context.mainExecutor,
                        object : TelephonyManager.CellInfoCallback() {
                            override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                                resumeOnce(continuation, completed, cellInfo.toList())
                            }
                        },
                    )
                }.isSuccess

                continuation.invokeOnCancellation {
                    completed.set(true)
                }

                if (!requested) {
                    resumeOnce(continuation, completed, emptyList())
                }
            }
        } ?: emptyList()
    }

    @Suppress("MissingPermission")
    private fun getCachedCellInfo(tm: TelephonyManager): List<CellInfo> {
        return runCatching { tm.allCellInfo.orEmpty() }.getOrDefault(emptyList())
    }

    private fun toLookupCandidate(info: CellInfo): CellLookupCandidate? {
        return when (info) {
            is CellInfoGsm -> {
                val identity = info.cellIdentity
                val mcc = gsmMcc(identity) ?: return null
                val mnc = gsmMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "gsm",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoLte -> {
                val identity = info.cellIdentity
                val mcc = lteMcc(identity) ?: return null
                val mnc = lteMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.tac) ?: return null
                val cellId = normalizeCellValue(identity.ci) ?: return null
                CellLookupCandidate(
                    radio = "lte",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoWcdma -> {
                val identity = info.cellIdentity
                val mcc = wcdmaMcc(identity) ?: return null
                val mnc = wcdmaMnc(identity) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "wcdma",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            else -> null
        }
    }

    private suspend fun collectWifiCandidates(context: Context): List<WifiLookupCandidate> {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cachedCandidates = currentWifiCandidates(wifiManager)
        val refreshedCandidates = requestFreshWifiScan(context, wifiManager)

        return (refreshedCandidates ?: cachedCandidates)
            .distinctBy { it.macAddress }
            .sortedByDescending { it.signalStrength ?: Int.MIN_VALUE }
            .take(MAX_WIFI_ACCESS_POINTS)
    }

    @Suppress("MissingPermission", "DEPRECATION")
    private suspend fun requestFreshWifiScan(
        context: Context,
        wifiManager: WifiManager,
    ): List<WifiLookupCandidate>? {
        val appContext = context.applicationContext
        return withTimeoutOrNull(WIFI_SCAN_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val completed = AtomicBoolean(false)
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(receiverContext: Context?, intent: Intent?) {
                        if (intent?.action != WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                            return
                        }
                        runCatching { appContext.unregisterReceiver(this) }
                        resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                    }
                }

                val registered = runCatching {
                    ContextCompat.registerReceiver(
                        appContext,
                        receiver,
                        IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                        ContextCompat.RECEIVER_NOT_EXPORTED,
                    )
                }.isSuccess

                if (!registered) {
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                    return@suspendCancellableCoroutine
                }

                continuation.invokeOnCancellation {
                    completed.set(true)
                    runCatching { appContext.unregisterReceiver(receiver) }
                }

                val started = runCatching { wifiManager.startScan() }.getOrDefault(false)
                if (!started) {
                    runCatching { appContext.unregisterReceiver(receiver) }
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                }
            }
        }
    }

    @Suppress("MissingPermission")
    private fun currentWifiCandidates(wifiManager: WifiManager): List<WifiLookupCandidate> {
        return runCatching {
            wifiManager.scanResults
                ?.mapNotNull(::toWifiLookupCandidate)
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun toWifiLookupCandidate(scanResult: ScanResult): WifiLookupCandidate? {
        val macAddress = normalizeMacAddress(scanResult.BSSID) ?: return null
        val ssid = normalizeSsid(scanResultSsid(scanResult)) ?: return null
        if (ssid.endsWith("_nomap", ignoreCase = true)) return null

        return WifiLookupCandidate(
            macAddress = macAddress,
            frequency = scanResult.frequency.takeIf { it > 0 },
            signalStrength = normalizeSignalStrength(scanResult.level),
        )
    }

    private fun normalizeOperatorCode(value: String?): String? {
        return value?.takeIf { it.isNotBlank() && it.all(Char::isDigit) }
    }

    private fun normalizeOperatorCode(value: Int): String? {
        return value
            .takeIf { it in 0 until Int.MAX_VALUE }
            ?.toString()
            ?.let(::normalizeOperatorCode)
    }

    private fun scanResultSsid(scanResult: ScanResult): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Api33Impl.scanResultSsid(scanResult)
        } else {
            @Suppress("DEPRECATION")
            scanResult.SSID
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    // Keep API 28-only operator accessors isolated so pre-P devices never resolve them.
    @RequiresApi(Build.VERSION_CODES.P)
    private object Api28Impl {
        @DoNotInline
        fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mncString)
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private object Api33Impl {
        @DoNotInline
        fun scanResultSsid(scanResult: ScanResult): String? {
            return scanResult.wifiSsid
                ?.toString()
                ?.trim('"')
        }
    }

    private fun normalizeCellValue(value: Int): Long? {
        return value.toLong().takeIf { it in 0 until Int.MAX_VALUE.toLong() }
    }

    private fun normalizeSignalStrength(value: Int): Int? {
        return value.takeIf { it in -150..0 }
    }

    private fun normalizeMacAddress(value: String?): String? {
        val normalized = value?.trim()?.lowercase(Locale.US) ?: return null
        if (normalized == PLACEHOLDER_BSSID) return null
        if (!MAC_ADDRESS_REGEX.matches(normalized)) return null
        return normalized
    }

    private fun normalizeSsid(value: String?): String? {
        val normalized = value?.trim().orEmpty()
        return normalized.takeIf {
            it.isNotEmpty() && !it.equals("<unknown ssid>", ignoreCase = true)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun <T> resumeOnce(
        continuation: CancellableContinuation<T>,
        completed: AtomicBoolean,
        value: T,
    ) {
        if (!completed.compareAndSet(false, true)) {
            return
        }
        continuation.resume(value) { }
    }

    @Suppress("DEPRECATION")
    private fun reverseGeocodeCountry(context: Context, latitude: Double, longitude: Double): String? {
        return runCatching {
            if (!Geocoder.isPresent()) {
                null
            } else {
                Geocoder(context, Locale.US)
                    .getFromLocation(latitude, longitude, 1)
                    ?.firstOrNull()
                    ?.countryCode
                    ?.uppercase(Locale.US)
            }
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun getBssid(context: Context): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return null
            val caps = cm.getNetworkCapabilities(network) ?: return null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
            (caps.transportInfo as? WifiInfo)?.bssid
        } else {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wm.connectionInfo?.bssid
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        if (snapshot.networkMcc == null) {
            findings += Finding("PLMN: network MCC is unavailable")
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase(Locale.US) ?: "N/A"
            val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC

            findings += Finding(
                description = "Network operator: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)",
                isInformational = true,
            )
            findings += Finding(
                description = "Network MCC: ${snapshot.networkMcc}",
                isInformational = true,
            )
            if (networkIsRussia) {
                findings += Finding("network_mcc_ru:true")
            }

            for (sim in snapshot.simCards) {
                val simCountry = sim.simCountryIso?.uppercase(Locale.US) ?: "N/A"
                val operatorPart = sim.operatorName?.let { ", $it" } ?: ""
                findings += Finding(
                    description = "SIM[${sim.slotIndex}] MCC: ${sim.simMcc ?: "N/A"} ($simCountry)$operatorPart",
                    isInformational = true,
                )
                when (sim.isRoaming) {
                    true -> findings += Finding("SIM[${sim.slotIndex}] Roaming: yes", isInformational = true)
                    false -> findings += Finding("SIM[${sim.slotIndex}] Roaming: no", isInformational = true)
                    null -> Unit
                }
            }

            if (!networkIsRussia) {
                val matchingSim = snapshot.simCards.firstOrNull { it.simMcc == snapshot.networkMcc }
                val confidence = if (matchingSim?.isRoaming == true) {
                    EvidenceConfidence.LOW
                } else {
                    EvidenceConfidence.MEDIUM
                }
                val description = "Network MCC ${snapshot.networkMcc} ($networkCountry) is not Russia"
                findings += Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.LOCATION_SIGNALS,
                    confidence = confidence,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.LOCATION_SIGNALS,
                    detected = true,
                    confidence = confidence,
                    description = description,
                )
                needsReview = true
            }
        }

        if (!snapshot.cellLookupPermissionGranted) {
            findings += Finding("Cell lookup: ACCESS_FINE_LOCATION permission is not granted")
        } else {
            findings += Finding("Cell lookup candidates: ${snapshot.cellCandidatesCount}")
            if (snapshot.cellCandidatesCount == 0) {
                findings += Finding("Cell lookup: base station identifiers are unavailable")
            }
        }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("Wi-Fi scan: permissions are not granted")
        } else {
            findings += Finding("Wi-Fi scan candidates: ${snapshot.wifiAccessPointCandidatesCount}")
            if (snapshot.wifiAccessPointCandidatesCount == 0) {
                findings += Finding("Wi-Fi scan: access points are unavailable")
            }
        }

        snapshot.cellCountryCode?.let { countryCode ->
            findings += Finding("Cell lookup country: $countryCode")
            if (countryCode == "RU") {
                findings += Finding("cell_country_ru:true")
                findings += Finding("location_country_ru:true")
            }
        }
        snapshot.cellLookupSummary?.let { findings += Finding(it) }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("BSSID: permission is not granted")
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings += Finding("BSSID: unavailable")
        } else {
            findings += Finding("BSSID: ${snapshot.bssid}")
        }

        return CategoryResult(
            name = "Location signals",
            detected = false,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private val MAC_ADDRESS_REGEX = Regex("^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
}
