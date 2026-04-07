# LocationSignalsChecker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PLMN/BSSID-based location checker that detects VPN usage by comparing cellular network country (MCC) with GeoIP results.

**Architecture:** New `LocationSignalsChecker` produces a `CategoryResult` alongside existing checkers. `VerdictEngine` uses Network MCC + GeoIP cross-reference to detect VPN (Network MCC == RU + GeoIP foreign = DETECTED). Permissions are requested via onboarding dialog on first launch, with a settings button to re-request.

**Tech Stack:** Android SDK (`TelephonyManager`, `WifiManager`, `ConnectivityManager`), `SharedPreferences`, `ActivityResultContracts`

---

### Task 1: Add `LOCATION_SIGNALS` to `EvidenceSource` and extend `CheckResult`

**Files:**
- Modify: `app/src/main/java/com/notcvnt/rknhardering/model/CheckResult.kt:15-26` (enum) and `:99-105` (data class)

- [ ] **Step 1: Add LOCATION_SIGNALS to EvidenceSource enum**

In `app/src/main/java/com/notcvnt/rknhardering/model/CheckResult.kt`, add `LOCATION_SIGNALS` to the `EvidenceSource` enum after `DNS`:

```kotlin
enum class EvidenceSource {
    GEO_IP,
    NETWORK_CAPABILITIES,
    SYSTEM_PROXY,
    INSTALLED_APP,
    VPN_SERVICE_DECLARATION,
    ACTIVE_VPN,
    LOCAL_PROXY,
    XRAY_API,
    SPLIT_TUNNEL_BYPASS,
    NETWORK_INTERFACE,
    ROUTING,
    DNS,
    DUMPSYS,
    LOCATION_SIGNALS,
}
```

- [ ] **Step 2: Add `locationSignals` field to `CheckResult`**

In the same file, add `locationSignals` to the `CheckResult` data class between `indirectSigns` and `bypassResult`:

```kotlin
data class CheckResult(
    val geoIp: CategoryResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val locationSignals: CategoryResult,
    val bypassResult: BypassResult,
    val verdict: Verdict,
)
```

- [ ] **Step 3: Fix compilation errors in tests**

The existing `VerdictEngineTest` does not construct `CheckResult` directly, so no changes needed there. But `MainActivity.kt:159` references `result.geoIp`, `result.directSigns`, `result.indirectSigns` - the new field will be used in Task 6. For now, verify the project compiles.

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`

Expected: Compilation errors in `MainActivity.kt` and `VpnCheckRunner.kt` because they construct `CheckResult` without the new field. These will be fixed in subsequent tasks.

- [ ] **Step 4: Fix `VpnCheckRunner` to pass a placeholder `locationSignals`**

In `app/src/main/java/com/notcvnt/rknhardering/checker/VpnCheckRunner.kt`, add the placeholder so the project compiles while we build the real checker:

```kotlin
package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        onBypassProgress: (suspend (BypassChecker.Progress) -> Unit)? = null,
    ): CheckResult = coroutineScope {
        val geoIpDeferred = async { GeoIpChecker.check() }
        val directDeferred = async { DirectSignsChecker.check(context) }
        val indirectDeferred = async { IndirectSignsChecker.check(context) }
        val bypassDeferred = async { BypassChecker.check(onProgress = onBypassProgress) }

        val geoIp = geoIpDeferred.await()
        val directSigns = directDeferred.await()
        val indirectSigns = indirectDeferred.await()
        val bypassResult = bypassDeferred.await()

        val locationSignals = CategoryResult(
            name = "Сигналы местоположения",
            detected = false,
            findings = emptyList(),
        )

        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            bypassResult = bypassResult,
        )

        CheckResult(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            verdict = verdict,
        )
    }
}
```

- [ ] **Step 5: Verify compilation**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 6: Run existing tests to verify nothing broke**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: All existing tests pass.

---

### Task 2: Write `LocationSignalsChecker` with unit tests (TDD)

**Files:**
- Create: `app/src/test/java/com/notcvnt/rknhardering/checker/LocationSignalsCheckerTest.kt`
- Create: `app/src/main/java/com/notcvnt/rknhardering/checker/LocationSignalsChecker.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/notcvnt/rknhardering/checker/LocationSignalsCheckerTest.kt`:

```kotlin
package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocationSignalsCheckerTest {

    @Test
    fun `russian network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("MegaFon") })
        assertTrue(result.findings.any { it.description.contains("ru", ignoreCase = true) })
    }

    @Test
    fun `foreign network mcc sets needsReview`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "244",
                simCountryIso = "fi",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `foreign sim roaming in russia produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "Beeline",
                simMcc = "244",
                simCountryIso = "fi",
                isRoaming = true,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
    }

    @Test
    fun `no sim produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.isEmpty())
    }

    @Test
    fun `phone permission denied skips plmn block`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simMcc = null,
                simCountryIso = null,
                isRoaming = null,
                bssid = null,
                phonePermissionGranted = false,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("разрешение", ignoreCase = true) })
    }

    @Test
    fun `location permission denied skips bssid block`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("разрешение", ignoreCase = true) })
    }

    @Test
    fun `valid bssid produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = "AA:BB:CC:DD:EE:FF",
                phonePermissionGranted = true,
                locationPermissionGranted = true,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("AA:BB:CC:DD:EE:FF") })
    }

    @Test
    fun `placeholder bssid 020000000000 treated as unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MTS",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = false,
                bssid = "02:00:00:00:00:00",
                phonePermissionGranted = true,
                locationPermissionGranted = true,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("BSSID") && it.description.contains("недоступен") })
    }

    @Test
    fun `foreign network mcc with roaming has lower confidence`() {
        val result = LocationSignalsChecker.evaluate(
            LocationSignalsChecker.LocationSnapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simMcc = "250",
                simCountryIso = "ru",
                isRoaming = true,
                bssid = null,
                phonePermissionGranted = true,
                locationPermissionGranted = false,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.LocationSignalsCheckerTest" 2>&1 | tail -5`
Expected: FAIL - class `LocationSignalsChecker` does not exist.

- [ ] **Step 3: Implement `LocationSignalsChecker`**

Create `app/src/main/java/com/notcvnt/rknhardering/checker/LocationSignalsChecker.kt`:

```kotlin
package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding

object LocationSignalsChecker {

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simMcc: String?,
        val simCountryIso: String?,
        val isRoaming: Boolean?,
        val bssid: String?,
        val phonePermissionGranted: Boolean,
        val locationPermissionGranted: Boolean,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"

    fun check(context: Context): CategoryResult {
        val snapshot = collectSnapshot(context)
        return evaluate(snapshot)
    }

    private fun collectSnapshot(context: Context): LocationSnapshot {
        val phoneGranted = ContextCompat.checkSelfPermission(
            context, Manifest.permission.READ_PHONE_STATE,
        ) == PackageManager.PERMISSION_GRANTED

        val locationPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }
        val locationGranted = ContextCompat.checkSelfPermission(
            context, locationPermission,
        ) == PackageManager.PERMISSION_GRANTED

        var networkMcc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var simMcc: String? = null
        var simCountryIso: String? = null
        var isRoaming: Boolean? = null

        if (phoneGranted) {
            try {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
                val networkOp = tm.networkOperator
                if (!networkOp.isNullOrEmpty() && networkOp.length >= 3) {
                    networkMcc = networkOp.substring(0, 3)
                }
                networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
                networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }
                val simOp = tm.simOperator
                if (!simOp.isNullOrEmpty() && simOp.length >= 3) {
                    simMcc = simOp.substring(0, 3)
                }
                simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() }
                isRoaming = tm.isNetworkRoaming
            } catch (_: Exception) {
                // SecurityException or other - treat as unavailable
            }
        }

        var bssid: String? = null
        if (locationGranted) {
            try {
                bssid = getBssid(context)
            } catch (_: Exception) {
                // treat as unavailable
            }
        }

        return LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simMcc = simMcc,
            simCountryIso = simCountryIso,
            isRoaming = isRoaming,
            bssid = bssid,
            phonePermissionGranted = phoneGranted,
            locationPermissionGranted = locationGranted,
        )
    }

    @Suppress("DEPRECATION")
    private fun getBssid(context: Context): String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return null
            val caps = cm.getNetworkCapabilities(network) ?: return null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
            val wifiInfo = caps.transportInfo as? WifiInfo ?: return null
            return wifiInfo.bssid
        } else {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val info = wm.connectionInfo ?: return null
            return info.bssid
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        // PLMN block
        if (!snapshot.phonePermissionGranted) {
            findings.add(Finding("PLMN: разрешение READ_PHONE_STATE не выдано"))
        } else if (snapshot.networkMcc == null) {
            findings.add(Finding("PLMN: SIM не обнаружена или сеть недоступна"))
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase() ?: "N/A"
            findings.add(Finding("Оператор сети: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)"))
            findings.add(Finding("Network MCC: ${snapshot.networkMcc}"))

            if (snapshot.simMcc != null) {
                val simCountry = snapshot.simCountryIso?.uppercase() ?: "N/A"
                findings.add(Finding("SIM MCC: ${snapshot.simMcc} ($simCountry)"))
            }

            if (snapshot.isRoaming == true) {
                findings.add(Finding("Роуминг: да"))
            } else if (snapshot.isRoaming == false) {
                findings.add(Finding("Роуминг: нет"))
            }

            val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC
            if (!networkIsRussia) {
                val confidence = if (snapshot.isRoaming == true) {
                    EvidenceConfidence.LOW
                } else {
                    EvidenceConfidence.MEDIUM
                }
                val desc = "Network MCC ${snapshot.networkMcc} ($networkCountry) - не Россия"
                findings.add(
                    Finding(
                        description = desc,
                        needsReview = true,
                        source = EvidenceSource.LOCATION_SIGNALS,
                        confidence = confidence,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.LOCATION_SIGNALS,
                        detected = true,
                        confidence = confidence,
                        description = desc,
                    ),
                )
                needsReview = true
            }
        }

        // BSSID block
        if (!snapshot.locationPermissionGranted) {
            findings.add(Finding("BSSID: разрешение не выдано"))
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings.add(Finding("BSSID: недоступен"))
        } else {
            findings.add(Finding("BSSID: ${snapshot.bssid}"))
        }

        return CategoryResult(
            name = "Сигналы местоположения",
            detected = false,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.LocationSignalsCheckerTest" 2>&1 | tail -10`
Expected: All 8 tests PASS.

- [ ] **Step 5: Run all tests**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: All tests PASS.

---

### Task 3: Integrate `LocationSignalsChecker` into `VpnCheckRunner`

**Files:**
- Modify: `app/src/main/java/com/notcvnt/rknhardering/checker/VpnCheckRunner.kt`

- [ ] **Step 1: Replace the placeholder with real checker call**

Replace the full content of `VpnCheckRunner.kt`:

```kotlin
package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        onBypassProgress: (suspend (BypassChecker.Progress) -> Unit)? = null,
    ): CheckResult = coroutineScope {
        val geoIpDeferred = async { GeoIpChecker.check() }
        val directDeferred = async { DirectSignsChecker.check(context) }
        val indirectDeferred = async { IndirectSignsChecker.check(context) }
        val locationDeferred = async { LocationSignalsChecker.check(context) }
        val bypassDeferred = async { BypassChecker.check(onProgress = onBypassProgress) }

        val geoIp = geoIpDeferred.await()
        val directSigns = directDeferred.await()
        val indirectSigns = indirectDeferred.await()
        val locationSignals = locationDeferred.await()
        val bypassResult = bypassDeferred.await()

        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
        )

        CheckResult(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            verdict = verdict,
        )
    }
}
```

Note: This will not compile until Task 4 updates `VerdictEngine.evaluate` to accept `locationSignals`. That is intentional - Task 4 follows immediately.

---

### Task 4: Update `VerdictEngine` with location signals logic (TDD)

**Files:**
- Modify: `app/src/test/java/com/notcvnt/rknhardering/checker/VerdictEngineTest.kt`
- Modify: `app/src/main/java/com/notcvnt/rknhardering/checker/VerdictEngine.kt`

- [ ] **Step 1: Add new test cases and update existing helpers**

Append the following test methods to `VerdictEngineTest.kt` and update the existing `evaluate` calls to pass the new `locationSignals` parameter.

First, update every existing call to `VerdictEngine.evaluate(...)` to include `locationSignals = category()` as a new parameter. There are 6 calls total - each needs the extra argument. For example the first test becomes:

```kotlin
@Test
fun `xray api evidence returns detected`() {
    val verdict = VerdictEngine.evaluate(
        geoIp = category(),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = category(),
        bypassResult = bypass(
            evidence = listOf(
                evidence(
                    source = EvidenceSource.XRAY_API,
                    confidence = EvidenceConfidence.HIGH,
                    kind = VpnAppKind.TARGETED_BYPASS,
                ),
            ),
        ),
    )

    assertEquals(Verdict.DETECTED, verdict)
}
```

Apply the same change (add `locationSignals = category(),` after `indirectSigns`) to all 6 existing tests.

Then add these new test methods:

```kotlin
@Test
fun `network mcc RU plus foreign geoip returns detected`() {
    val locationEvidence = evidence(
        source = EvidenceSource.LOCATION_SIGNALS,
        confidence = EvidenceConfidence.MEDIUM,
    )
    val geoEvidence = evidence(
        source = EvidenceSource.GEO_IP,
        confidence = EvidenceConfidence.MEDIUM,
    )

    val verdict = VerdictEngine.evaluate(
        geoIp = category(evidence = listOf(geoEvidence)),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = locationCategory(networkMccRu = true),
        bypassResult = bypass(),
    )

    assertEquals(Verdict.DETECTED, verdict)
}

@Test
fun `network mcc RU foreign sim roaming plus foreign geoip returns detected`() {
    val geoEvidence = evidence(
        source = EvidenceSource.GEO_IP,
        confidence = EvidenceConfidence.MEDIUM,
    )

    val verdict = VerdictEngine.evaluate(
        geoIp = category(evidence = listOf(geoEvidence)),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = locationCategory(networkMccRu = true),
        bypassResult = bypass(),
    )

    assertEquals(Verdict.DETECTED, verdict)
}

@Test
fun `foreign network mcc plus foreign geoip returns not detected`() {
    val locationEvidence = evidence(
        source = EvidenceSource.LOCATION_SIGNALS,
        confidence = EvidenceConfidence.MEDIUM,
    )
    val geoEvidence = evidence(
        source = EvidenceSource.GEO_IP,
        confidence = EvidenceConfidence.MEDIUM,
    )

    val verdict = VerdictEngine.evaluate(
        geoIp = category(evidence = listOf(geoEvidence), needsReview = true),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = category(evidence = listOf(locationEvidence), needsReview = true),
        bypassResult = bypass(),
    )

    // Foreign MCC + foreign GeoIP = person is abroad, not VPN
    // Score from 2 MEDIUM evidence items = 6, so NEEDS_REVIEW from score threshold
    assertEquals(Verdict.NEEDS_REVIEW, verdict)
}

@Test
fun `empty location signals does not affect verdict`() {
    val verdict = VerdictEngine.evaluate(
        geoIp = category(),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = category(),
        bypassResult = bypass(),
    )

    assertEquals(Verdict.NOT_DETECTED, verdict)
}

@Test
fun `network mcc RU without foreign geoip returns not detected`() {
    val verdict = VerdictEngine.evaluate(
        geoIp = category(),
        directSigns = category(),
        indirectSigns = category(),
        locationSignals = locationCategory(networkMccRu = true),
        bypassResult = bypass(),
    )

    assertEquals(Verdict.NOT_DETECTED, verdict)
}
```

And add this helper method to the test class:

```kotlin
private fun locationCategory(
    networkMccRu: Boolean,
    evidence: List<EvidenceItem> = emptyList(),
): CategoryResult {
    val findings = if (networkMccRu) {
        listOf(Finding("Network MCC: 250"), Finding("network_mcc_ru:true"))
    } else {
        listOf(Finding("Network MCC: 244"))
    }
    return CategoryResult(
        name = "Сигналы местоположения",
        detected = false,
        findings = findings,
        needsReview = !networkMccRu,
        evidence = evidence,
    )
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.VerdictEngineTest" 2>&1 | tail -10`
Expected: Compilation error - `evaluate` does not accept `locationSignals`.

- [ ] **Step 3: Update `VerdictEngine.evaluate` to accept and use `locationSignals`**

Replace `app/src/main/java/com/notcvnt/rknhardering/checker/VerdictEngine.kt`:

```kotlin
package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppKind

object VerdictEngine {

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
    ): Verdict {
        val evidence = buildList {
            addAll(geoIp.evidence)
            addAll(directSigns.evidence)
            addAll(indirectSigns.evidence)
            addAll(locationSignals.evidence)
            addAll(bypassResult.evidence)
        }

        if (evidence.any { it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS && it.detected }) {
            return Verdict.DETECTED
        }
        if (evidence.any { it.source == EvidenceSource.XRAY_API && it.detected }) {
            return Verdict.DETECTED
        }

        // Location signals: Network MCC is RU + GeoIP is foreign -> DETECTED
        val networkMccIsRu = locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true")
        }
        val hasGeo = evidence.any { it.source == EvidenceSource.GEO_IP && it.detected }
        if (networkMccIsRu && hasGeo) {
            return Verdict.DETECTED
        }

        val hasStrongTransport = evidence.any {
            it.source == EvidenceSource.NETWORK_CAPABILITIES && it.confidence == EvidenceConfidence.HIGH
        }
        val hasLocalProxy = evidence.any { it.source == EvidenceSource.LOCAL_PROXY && it.detected }
        val hasTargetedInstalled = evidence.any {
            it.source == EvidenceSource.INSTALLED_APP && it.kind == VpnAppKind.TARGETED_BYPASS
        }
        val hasTargetedActive = evidence.any {
            it.source == EvidenceSource.ACTIVE_VPN && it.kind == VpnAppKind.TARGETED_BYPASS
        }
        val hasGenericActive = evidence.any {
            it.source == EvidenceSource.ACTIVE_VPN && it.kind == VpnAppKind.GENERIC_VPN
        }

        if (hasTargetedActive && (hasLocalProxy || hasStrongTransport || hasGeo || hasTargetedInstalled)) {
            return Verdict.DETECTED
        }

        if (hasGeo && (hasStrongTransport || hasLocalProxy || hasTargetedActive)) {
            return Verdict.DETECTED
        }

        val score = evidence.sumOf(::weight)
        return when {
            score >= 11 && (hasTargetedInstalled || hasTargetedActive || hasLocalProxy) -> Verdict.DETECTED
            hasGenericActive || score >= 4 || directSigns.needsReview || indirectSigns.needsReview -> Verdict.NEEDS_REVIEW
            else -> Verdict.NOT_DETECTED
        }
    }

    private fun weight(item: EvidenceItem): Int {
        val confidenceWeight = when (item.confidence) {
            EvidenceConfidence.HIGH -> 5
            EvidenceConfidence.MEDIUM -> 3
            EvidenceConfidence.LOW -> 1
        }
        val kindWeight = when (item.kind) {
            VpnAppKind.TARGETED_BYPASS -> 2
            VpnAppKind.GENERIC_VPN -> 0
            null -> 0
        }
        val sourceWeight = when (item.source) {
            EvidenceSource.ACTIVE_VPN -> 2
            EvidenceSource.LOCAL_PROXY -> 2
            EvidenceSource.XRAY_API -> 4
            EvidenceSource.SPLIT_TUNNEL_BYPASS -> 5
            else -> 0
        }
        return confidenceWeight + kindWeight + sourceWeight
    }
}
```

**Important design note:** The `networkMccIsRu` flag is communicated from `LocationSignalsChecker` via a finding with text `"network_mcc_ru:true"`. This is a machine-readable marker added by `LocationSignalsChecker.evaluate()` when Network MCC == "250". Update `LocationSignalsChecker.evaluate()` to add this marker:

In `LocationSignalsChecker.kt`, inside the `evaluate` function, after the line `findings.add(Finding("Network MCC: ${snapshot.networkMcc}"))`, add:

```kotlin
if (networkIsRussia) {
    findings.add(Finding("network_mcc_ru:true"))
}
```

Move the `val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC` line to before the findings so it's available. The full block becomes:

```kotlin
} else {
    val networkCountry = snapshot.networkCountryIso?.uppercase() ?: "N/A"
    val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC

    findings.add(Finding("Оператор сети: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)"))
    findings.add(Finding("Network MCC: ${snapshot.networkMcc}"))
    if (networkIsRussia) {
        findings.add(Finding("network_mcc_ru:true"))
    }

    if (snapshot.simMcc != null) {
        val simCountry = snapshot.simCountryIso?.uppercase() ?: "N/A"
        findings.add(Finding("SIM MCC: ${snapshot.simMcc} ($simCountry)"))
    }
    // ... rest unchanged
```

- [ ] **Step 4: Run all tests**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: All tests PASS.

- [ ] **Step 5: Verify compilation**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL.

---

### Task 5: Add permissions to AndroidManifest.xml

**Files:**
- Modify: `app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Add permission declarations**

In `app/src/main/AndroidManifest.xml`, add the three new permissions after the existing `ACCESS_NETWORK_STATE` line:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"
    android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />
```

- [ ] **Step 2: Verify compilation**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL.

---

### Task 6: Add Location Signals card to UI layout

**Files:**
- Modify: `app/src/main/res/layout/activity_main.xml`

- [ ] **Step 1: Add the Location Signals card after the Indirect Signs card**

In `activity_main.xml`, after the closing `</com.google.android.material.card.MaterialCardView>` of `cardIndirect` (line 239) and before the Bypass Card comment (line 241), insert:

```xml
        <!-- Location Signals Card -->
        <com.google.android.material.card.MaterialCardView
            android:id="@+id/cardLocation"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:layout_marginBottom="12dp"
            android:visibility="gone">

            <LinearLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="vertical"
                android:padding="16dp">

                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:gravity="center_vertical"
                    android:orientation="horizontal">

                    <ImageView
                        android:id="@+id/iconLocation"
                        android:layout_width="24dp"
                        android:layout_height="24dp"
                        android:layout_marginEnd="8dp"
                        android:contentDescription="status" />

                    <TextView
                        android:layout_width="0dp"
                        android:layout_height="wrap_content"
                        android:layout_weight="1"
                        android:text="Сигналы местоположения"
                        android:textColor="?android:attr/textColorPrimary"
                        android:textSize="18sp"
                        android:textStyle="bold" />

                    <TextView
                        android:id="@+id/statusLocation"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:textSize="14sp" />
                </LinearLayout>

                <LinearLayout
                    android:id="@+id/findingsLocation"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_marginTop="8dp"
                    android:orientation="vertical" />
            </LinearLayout>
        </com.google.android.material.card.MaterialCardView>
```

- [ ] **Step 2: Verify compilation**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL.

---

### Task 7: Integrate permissions flow and new card into MainActivity

**Files:**
- Modify: `app/src/main/java/com/notcvnt/rknhardering/MainActivity.kt`

- [ ] **Step 1: Add imports, fields, permission launcher, and onboarding dialog**

Replace the full content of `MainActivity.kt`:

```kotlin
package com.notcvnt.rknhardering

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.checker.BypassChecker
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.Verdict
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var btnRunCheck: MaterialButton
    private lateinit var btnStopCheck: MaterialButton
    private lateinit var btnReRequestPermissions: MaterialButton
    private lateinit var linkGithub: TextView
    private var checkJob: Job? = null
    private lateinit var progressBar: ProgressBar
    private lateinit var cardGeoIp: MaterialCardView
    private lateinit var cardDirect: MaterialCardView
    private lateinit var cardIndirect: MaterialCardView
    private lateinit var cardLocation: MaterialCardView
    private lateinit var cardVerdict: MaterialCardView
    private lateinit var iconGeoIp: ImageView
    private lateinit var iconDirect: ImageView
    private lateinit var iconIndirect: ImageView
    private lateinit var iconLocation: ImageView
    private lateinit var statusGeoIp: TextView
    private lateinit var statusDirect: TextView
    private lateinit var statusIndirect: TextView
    private lateinit var statusLocation: TextView
    private lateinit var findingsGeoIp: LinearLayout
    private lateinit var findingsDirect: LinearLayout
    private lateinit var findingsIndirect: LinearLayout
    private lateinit var findingsLocation: LinearLayout
    private lateinit var cardBypass: MaterialCardView
    private lateinit var iconBypass: ImageView
    private lateinit var statusBypass: TextView
    private lateinit var textBypassProgress: TextView
    private lateinit var findingsBypass: LinearLayout
    private lateinit var iconVerdict: ImageView
    private lateinit var textVerdict: TextView

    private val prefs by lazy { getSharedPreferences("rknhardering_prefs", MODE_PRIVATE) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { _ ->
        prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, true).apply()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        bindViews()

        linkGithub.setOnClickListener { openGithubRepo() }
        btnRunCheck.setOnClickListener { onRunCheckClicked() }
        btnStopCheck.setOnClickListener { checkJob?.cancel() }
        btnReRequestPermissions.setOnClickListener { reRequestPermissions() }

        if (!prefs.getBoolean(PREF_RATIONALE_SHOWN, false)) {
            showPermissionRationale()
        }
    }

    private fun bindViews() {
        btnRunCheck = findViewById(R.id.btnRunCheck)
        btnStopCheck = findViewById(R.id.btnStopCheck)
        btnReRequestPermissions = findViewById(R.id.btnReRequestPermissions)
        linkGithub = findViewById(R.id.linkGithub)
        progressBar = findViewById(R.id.progressBar)
        cardGeoIp = findViewById(R.id.cardGeoIp)
        cardDirect = findViewById(R.id.cardDirect)
        cardIndirect = findViewById(R.id.cardIndirect)
        cardLocation = findViewById(R.id.cardLocation)
        cardVerdict = findViewById(R.id.cardVerdict)
        iconGeoIp = findViewById(R.id.iconGeoIp)
        iconDirect = findViewById(R.id.iconDirect)
        iconIndirect = findViewById(R.id.iconIndirect)
        iconLocation = findViewById(R.id.iconLocation)
        statusGeoIp = findViewById(R.id.statusGeoIp)
        statusDirect = findViewById(R.id.statusDirect)
        statusIndirect = findViewById(R.id.statusIndirect)
        statusLocation = findViewById(R.id.statusLocation)
        findingsGeoIp = findViewById(R.id.findingsGeoIp)
        findingsDirect = findViewById(R.id.findingsDirect)
        findingsIndirect = findViewById(R.id.findingsIndirect)
        findingsLocation = findViewById(R.id.findingsLocation)
        cardBypass = findViewById(R.id.cardBypass)
        iconBypass = findViewById(R.id.iconBypass)
        statusBypass = findViewById(R.id.statusBypass)
        textBypassProgress = findViewById(R.id.textBypassProgress)
        findingsBypass = findViewById(R.id.findingsBypass)
        iconVerdict = findViewById(R.id.iconVerdict)
        textVerdict = findViewById(R.id.textVerdict)
    }

    private fun openGithubRepo() {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.github_repo_url))))
    }

    private fun requiredPermissions(): Array<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            arrayOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun showPermissionRationale() {
        AlertDialog.Builder(this)
            .setTitle("Дополнительные разрешения")
            .setMessage(
                "Для повышения точности проверки приложению нужны дополнительные разрешения:\n\n" +
                    "\u2022 Состояние телефона - определяет страну сотового оператора для сравнения " +
                    "с IP-геолокацией. Например, Госуслуги запрашивает это разрешение для " +
                    "верификации региона при входе.\n\n" +
                    "\u2022 Местоположение - считывает идентификатор Wi-Fi точки доступа (BSSID) " +
                    "для уточнения местоположения. Например, 2ГИС запрашивает это разрешение " +
                    "для построения маршрута.\n\n" +
                    "Без этих разрешений проверка будет работать, но с меньшей точностью.",
            )
            .setPositiveButton("Разрешить") { _, _ ->
                permissionLauncher.launch(requiredPermissions())
            }
            .setNegativeButton("Пропустить") { _, _ ->
                prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, true).apply()
            }
            .setCancelable(false)
            .show()
    }

    private fun reRequestPermissions() {
        val perms = requiredPermissions()
        val allGranted = perms.all {
            ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }
        if (allGranted) {
            Toast.makeText(this, "Все разрешения уже выданы", Toast.LENGTH_SHORT).show()
            return
        }

        val canAsk = perms.any { shouldShowRequestPermissionRationale(it) }
        if (canAsk) {
            prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, false).apply()
            showPermissionRationale()
        } else {
            Toast.makeText(
                this,
                "Разрешение заблокировано. Откройте настройки приложения.",
                Toast.LENGTH_LONG,
            ).show()
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", packageName, null)
            }
            startActivity(intent)
        }
    }

    private fun onRunCheckClicked() {
        runCheck()
    }

    private fun runCheck() {
        btnRunCheck.isEnabled = false
        btnStopCheck.visibility = View.VISIBLE
        progressBar.visibility = View.VISIBLE
        hideCards()

        cardBypass.visibility = View.VISIBLE
        iconBypass.setImageResource(R.drawable.ic_help)
        statusBypass.text = "Сканирование..."
        statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        textBypassProgress.visibility = View.VISIBLE
        textBypassProgress.text = "Подготовка..."
        findingsBypass.removeAllViews()

        checkJob = lifecycleScope.launch {
            try {
                val result = VpnCheckRunner.run(this@MainActivity) { progress ->
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                        textBypassProgress.text = "${progress.phase}: ${progress.detail}"
                    }
                }
                progressBar.visibility = View.GONE
                btnStopCheck.visibility = View.GONE
                btnRunCheck.isEnabled = true
                displayResult(result)
            } catch (e: kotlinx.coroutines.CancellationException) {
                progressBar.visibility = View.GONE
                btnStopCheck.visibility = View.GONE
                btnRunCheck.isEnabled = true
                textBypassProgress.visibility = View.GONE
                statusBypass.text = "Отменено"
                statusBypass.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.verdict_yellow))
                throw e
            }
        }
    }

    private fun hideCards() {
        cardGeoIp.visibility = View.GONE
        cardDirect.visibility = View.GONE
        cardIndirect.visibility = View.GONE
        cardLocation.visibility = View.GONE
        cardBypass.visibility = View.GONE
        cardVerdict.visibility = View.GONE
    }

    private fun displayResult(result: CheckResult) {
        displayCategory(result.geoIp, cardGeoIp, iconGeoIp, statusGeoIp, findingsGeoIp)
        displayCategory(result.directSigns, cardDirect, iconDirect, statusDirect, findingsDirect)
        displayCategory(result.indirectSigns, cardIndirect, iconIndirect, statusIndirect, findingsIndirect)
        displayCategory(result.locationSignals, cardLocation, iconLocation, statusLocation, findingsLocation)
        displayBypass(result.bypassResult)
        displayVerdict(result.verdict)
    }

    private fun displayCategory(
        category: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
    ) {
        card.visibility = View.VISIBLE

        if (category.detected) {
            icon.setImageResource(R.drawable.ic_warning)
            status.text = "Обнаружено"
            status.setTextColor(ContextCompat.getColor(this, R.color.finding_detected))
        } else if (category.needsReview) {
            icon.setImageResource(R.drawable.ic_help)
            status.text = "Требует проверки"
            status.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        } else {
            icon.setImageResource(R.drawable.ic_check_circle)
            status.text = "Чисто"
            status.setTextColor(ContextCompat.getColor(this, R.color.finding_ok))
        }

        findingsContainer.removeAllViews()
        for (finding in category.findings) {
            if (finding.description.startsWith("network_mcc_ru:")) continue
            findingsContainer.addView(createFindingView(finding))
        }
    }

    private fun createFindingView(finding: Finding): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val indicator = TextView(this).apply {
            text = when {
                finding.detected -> "\u26A0"
                finding.needsReview -> "?"
                else -> "\u2713"
            }
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    when {
                        finding.detected -> R.color.finding_detected
                        finding.needsReview -> R.color.verdict_yellow
                        else -> R.color.finding_ok
                    },
                ),
            )
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
        }

        val description = TextView(this).apply {
            text = finding.description
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        row.addView(indicator)
        row.addView(description)
        return row
    }

    private fun displayBypass(bypass: BypassResult) {
        cardBypass.visibility = View.VISIBLE
        textBypassProgress.visibility = View.GONE

        if (bypass.detected) {
            iconBypass.setImageResource(R.drawable.ic_warning)
            statusBypass.text = "Обнаружено"
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.finding_detected))
        } else if (bypass.needsReview) {
            iconBypass.setImageResource(R.drawable.ic_help)
            statusBypass.text = "Требует проверки"
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        } else {
            iconBypass.setImageResource(R.drawable.ic_check_circle)
            statusBypass.text = "Чисто"
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.finding_ok))
        }

        findingsBypass.removeAllViews()
        for (finding in bypass.findings) {
            findingsBypass.addView(createFindingView(finding))
        }
    }

    private fun displayVerdict(verdict: Verdict) {
        cardVerdict.visibility = View.VISIBLE

        when (verdict) {
            Verdict.NOT_DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_check_circle)
                textVerdict.text = "Обход не выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_green))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_green_bg),
                )
            }
            Verdict.NEEDS_REVIEW -> {
                iconVerdict.setImageResource(R.drawable.ic_help)
                textVerdict.text = "Требуется дополнительная проверка"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_yellow_bg),
                )
            }
            Verdict.DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_error)
                textVerdict.text = "Обход выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_red))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_red_bg),
                )
            }
        }
    }

    private val Int.dp: Int
        get() = (this * resources.displayMetrics.density).toInt()

    companion object {
        private const val PREF_RATIONALE_SHOWN = "permissions_rationale_shown"
    }
}
```

- [ ] **Step 2: Add the "Re-request permissions" button to the layout**

In `activity_main.xml`, after the `btnStopCheck` closing tag (inside the horizontal LinearLayout with the buttons) and before the closing `</LinearLayout>` of that button container, add:

```xml
            <com.google.android.material.button.MaterialButton
                android:id="@+id/btnReRequestPermissions"
                style="@style/Widget.Material3.Button.TextButton"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:layout_marginStart="8dp"
                android:text="Разрешения"
                android:textAllCaps="false" />
```

- [ ] **Step 3: Verify compilation**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:compileDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Run all tests**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: All tests PASS.

- [ ] **Step 5: Run lint check**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:lintDebug 2>&1 | tail -10`
Expected: No new errors introduced (warnings are acceptable).

---

### Task 8: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Full clean build**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew clean :app:assembleDebug 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 2: Full test suite**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest 2>&1 | tail -10`
Expected: All tests PASS.

- [ ] **Step 3: Verify the new `LocationSignalsCheckerTest` runs all 8 tests**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.LocationSignalsCheckerTest" 2>&1 | tail -15`
Expected: 8 tests PASS.

- [ ] **Step 4: Verify updated `VerdictEngineTest` runs all tests**

Run: `cd /c/Users/usedcvnt/AndroidStudioProjects/RKNHardering && ./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.VerdictEngineTest" 2>&1 | tail -15`
Expected: 11 tests PASS (6 existing + 5 new).
