# LocationSignalsChecker Design Spec

## Summary

Add a new `LocationSignalsChecker` that determines the device's country via cellular network identity (PLMN/MCC) and Wi-Fi access point identifier (BSSID). This is an alternative geolocation source described in section 5.5 of the methodology. It supplements GeoIP, does not replace it. The primary detection case: device is connected to a Russian cellular operator (Network MCC == 250) but GeoIP reports a foreign IP, which indicates VPN usage.

## 1. Permissions and Onboarding

### Required permissions

| Permission | Purpose | API level |
|---|---|---|
| `READ_PHONE_STATE` | Access `TelephonyManager`: `getNetworkOperator()`, `getNetworkCountryIso()`, `getSimOperator()`, `getSimCountryIso()` | All |
| `ACCESS_FINE_LOCATION` | Access Wi-Fi BSSID via `WifiInfo` | < 33 |
| `NEARBY_WIFI_DEVICES` | Access Wi-Fi BSSID via `WifiInfo` | 33+ |

`isNetworkRoaming()` requires only `ACCESS_NETWORK_STATE` which is already in the manifest.

### Onboarding dialog (first launch only)

Shown once. Tracked via `SharedPreferences` key `permissions_rationale_shown`.

Dialog content:
- READ_PHONE_STATE explanation: "Determines the country of the cellular operator to compare with IP geolocation. For example, Gosuslugi (Gosuslugi) requests this permission for region verification at login."
- ACCESS_FINE_LOCATION / NEARBY_WIFI_DEVICES explanation: "Reads the Wi-Fi access point identifier (BSSID) to refine location. For example, 2GIS requests this permission for route building."
- Two buttons: "Allow" (triggers system permission dialogs) / "Skip" (checker works without this data).

After the dialog (granted or denied): set `permissions_rationale_shown = true`.

### Subsequent launches

No re-prompt. `LocationSignalsChecker` checks `checkSelfPermission` at runtime and silently skips blocks where permission is missing.

### Settings: "Re-request permissions" button

1. Resets `permissions_rationale_shown = false`.
2. Checks `shouldShowRequestPermissionRationale`:
   - `true` or never requested: show onboarding dialog then system request.
   - `false` ("Don't ask again" was selected): show toast "Permission blocked, open settings" and launch `Settings.ACTION_APPLICATION_DETAILS_SETTINGS`.

### API level adaptation

- API < 33: request `READ_PHONE_STATE` + `ACCESS_FINE_LOCATION`
- API 33+: request `READ_PHONE_STATE` + `NEARBY_WIFI_DEVICES`

## 2. LocationSignalsChecker Architecture

### Public API

```kotlin
object LocationSignalsChecker {
    suspend fun check(context: Context): CategoryResult
}
```

### Internal snapshot

```kotlin
internal data class LocationSnapshot(
    val networkMcc: String?,          // "250"
    val networkCountryIso: String?,   // "ru"
    val networkOperatorName: String?, // "MegaFon"
    val simMcc: String?,              // "244"
    val simCountryIso: String?,       // "fi"
    val isRoaming: Boolean?,
    val bssid: String?,               // "AA:BB:CC:DD:EE:FF" or null
    val phonePermissionGranted: Boolean,
    val locationPermissionGranted: Boolean,
)
```

### PLMN block (READ_PHONE_STATE)

1. Check permission via `ContextCompat.checkSelfPermission`.
2. Get `TelephonyManager` from context.
3. `getNetworkCountryIso()` -> ISO country of current network (physical location).
4. `getNetworkOperator()` -> MCC+MNC string; MCC = first 3 chars.
5. `getNetworkOperatorName()` -> operator display name.
6. `getSimCountryIso()` -> ISO country of SIM card (home operator).
7. `getSimOperator()` -> SIM MCC+MNC.
8. `isNetworkRoaming()` -> roaming status (no extra permission needed).
9. Generate findings with operator info.
10. If permission denied: finding "Permission not granted", skip block.

### BSSID block (ACCESS_FINE_LOCATION / NEARBY_WIFI_DEVICES)

1. Check permission with API level awareness.
2. Get `WifiInfo`:
   - API 31+: `ConnectivityManager.getNetworkCapabilities(activeNetwork)` -> `getTransportInfo()` cast to `WifiInfo`.
   - API < 31: `WifiManager.getConnectionInfo()` (deprecated but functional).
3. Read `wifiInfo.bssid`:
   - `null` or `"02:00:00:00:00:00"` -> finding "BSSID unavailable".
   - Valid BSSID -> informational finding (logged, not a VPN signal by itself).
4. If permission denied: finding "Permission not granted", skip block.

### Detection behavior

The checker itself never sets `detected = true`. It only sets `needsReview` in specific cases:
- Network MCC != "250" (not Russia) -> `needsReview = true`

All detection decisions are made by `VerdictEngine` based on cross-referencing with GeoIP results.

### EvidenceSource

Add `LOCATION_SIGNALS` to the existing `EvidenceSource` enum.

## 3. VerdictEngine Integration

### Decision matrix (LocationSignals + GeoIP contribution)

| Network MCC | SIM MCC | Roaming | GeoIP Country | Verdict contribution |
|---|---|---|---|---|
| RU | RU | - | RU | NOT_DETECTED |
| RU | RU | - | Foreign | **DETECTED** |
| RU | != RU | true | RU | NOT_DETECTED (foreign SIM roaming in Russia, normal) |
| RU | != RU | true | Foreign | **DETECTED** (physically in Russia per cell tower, but IP abroad) |
| != RU | any | - | Foreign | NOT_DETECTED (abroad) |
| != RU | RU | true | RU | NOT_DETECTED (Russian SIM roaming abroad, IP via operator CGNAT in Russia) |
| != RU | any | false | RU | NEEDS_REVIEW (foreign network, not roaming, but Russian IP) |
| No SIM | - | - | any | Skip, no data |

The existing verdict logic (GeoIP + direct signs + indirect signs + bypass) remains unchanged. Location signals provide an additional input: when Network MCC == RU and GeoIP is foreign, this raises the verdict to DETECTED regardless of other signals.

When location signals data is unavailable (permissions denied or no SIM), the verdict falls back to the existing behavior with no degradation.

## 4. Data Model Changes

### `CheckResult.kt`

Add to `EvidenceSource` enum:
```kotlin
LOCATION_SIGNALS,
```

Extend `CheckResult`:
```kotlin
data class CheckResult(
    val geoIp: CategoryResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val locationSignals: CategoryResult,  // new
    val bypassResult: BypassResult,
    val verdict: Verdict,
)
```

### `VpnCheckRunner.kt`

Add fifth `async` block launching `LocationSignalsChecker.check(context)`. Pass result to `VerdictEngine.evaluate()` as new parameter.

### `VerdictEngine.kt`

Accept `locationSignals: CategoryResult`. Implement the matrix from section 3.

### `MainActivity.kt`

- Onboarding dialog with permission rationale.
- `ActivityResultLauncher<Array<String>>` for `RequestMultiplePermissions`.
- Settings section with "Re-request permissions" button.
- Render `locationSignals` category in results UI alongside existing categories.

### `AndroidManifest.xml`

```xml
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"
    android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />
```

## 5. Testing

### Unit tests: `LocationSignalsCheckerTest.kt`

Test the pure `evaluate(snapshot)` function:
- Network MCC "250" -> findings contain country "ru", no evidence.
- Network MCC "244" + roaming true -> findings with needsReview=false.
- Network MCC null (no SIM) -> findings "SIM not found", empty evidence.
- Phone permission denied -> finding "permission not granted", PLMN block skipped.
- Location permission denied -> finding "permission not granted", BSSID block skipped.
- BSSID "02:00:00:00:00:00" -> finding "BSSID unavailable".
- BSSID valid -> informational finding.

### Unit tests: `VerdictEngineTest.kt` (updated)

Add cases for the matrix:
- Network MCC RU + GeoIP foreign -> DETECTED.
- Network MCC RU + SIM != RU + roaming + GeoIP foreign -> DETECTED.
- Network MCC != RU + GeoIP foreign -> verdict unchanged (NOT_DETECTED from location signals).
- Network MCC != RU + roaming + GeoIP RU -> NOT_DETECTED.
- locationSignals empty (no permissions) -> verdict unchanged relative to current behavior.

### No instrumented tests

`TelephonyManager` and `WifiManager` depend on real hardware.

## 6. File Summary

### New files
- `app/src/main/java/com/notcvnt/rknhardering/checker/LocationSignalsChecker.kt`
- `app/src/test/java/com/notcvnt/rknhardering/checker/LocationSignalsCheckerTest.kt`

### Modified files
- `app/src/main/java/com/notcvnt/rknhardering/model/CheckResult.kt`
- `app/src/main/java/com/notcvnt/rknhardering/checker/VpnCheckRunner.kt`
- `app/src/main/java/com/notcvnt/rknhardering/checker/VerdictEngine.kt`
- `app/src/test/java/com/notcvnt/rknhardering/checker/VerdictEngineTest.kt`
- `app/src/main/java/com/notcvnt/rknhardering/MainActivity.kt`
- `app/src/main/AndroidManifest.xml`

### No new dependencies

All functionality uses standard Android SDK APIs.
