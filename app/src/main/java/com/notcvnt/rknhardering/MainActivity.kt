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
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
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
    private lateinit var cardIpComparison: MaterialCardView
    private lateinit var cardDirect: MaterialCardView
    private lateinit var cardIndirect: MaterialCardView
    private lateinit var cardLocation: MaterialCardView
    private lateinit var cardVerdict: MaterialCardView
    private lateinit var iconGeoIp: ImageView
    private lateinit var iconIpComparison: ImageView
    private lateinit var iconDirect: ImageView
    private lateinit var iconIndirect: ImageView
    private lateinit var iconLocation: ImageView
    private lateinit var statusGeoIp: TextView
    private lateinit var statusIpComparison: TextView
    private lateinit var statusDirect: TextView
    private lateinit var statusIndirect: TextView
    private lateinit var statusLocation: TextView
    private lateinit var textIpComparisonSummary: TextView
    private lateinit var findingsGeoIp: LinearLayout
    private lateinit var ipComparisonGroups: LinearLayout
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
    private lateinit var geoIpInfoSection: LinearLayout
    private lateinit var geoIpDivider: View

    private val prefs by lazy { getSharedPreferences("rknhardering_prefs", MODE_PRIVATE) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        markPermissionsRequested(result.keys)
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
        cardIpComparison = findViewById(R.id.cardIpComparison)
        cardDirect = findViewById(R.id.cardDirect)
        cardIndirect = findViewById(R.id.cardIndirect)
        cardLocation = findViewById(R.id.cardLocation)
        cardVerdict = findViewById(R.id.cardVerdict)
        iconGeoIp = findViewById(R.id.iconGeoIp)
        iconIpComparison = findViewById(R.id.iconIpComparison)
        iconDirect = findViewById(R.id.iconDirect)
        iconIndirect = findViewById(R.id.iconIndirect)
        iconLocation = findViewById(R.id.iconLocation)
        statusGeoIp = findViewById(R.id.statusGeoIp)
        statusIpComparison = findViewById(R.id.statusIpComparison)
        statusDirect = findViewById(R.id.statusDirect)
        statusIndirect = findViewById(R.id.statusIndirect)
        statusLocation = findViewById(R.id.statusLocation)
        textIpComparisonSummary = findViewById(R.id.textIpComparisonSummary)
        findingsGeoIp = findViewById(R.id.findingsGeoIp)
        ipComparisonGroups = findViewById(R.id.ipComparisonGroups)
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
        geoIpInfoSection = findViewById(R.id.geoIpInfoSection)
        geoIpDivider = findViewById(R.id.geoIpDivider)
    }

    private fun openGithubRepo() {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.github_repo_url))))
    }

    private fun requiredPermissions(): Array<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun showPermissionRationale(permissions: Array<String> = requiredPermissions()) {
        AlertDialog.Builder(this)
            .setTitle("\u0414\u043e\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043d\u0438\u0435")
            .setMessage(permissionRationaleMessage())
            .setPositiveButton("Разрешить") { _, _ ->
                launchPermissionRequest(permissions)
            }
            .setNegativeButton("Пропустить") { _, _ ->
                prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, true).apply()
            }
            .setCancelable(false)
            .show()
    }

    private fun permissionRationaleMessage(): String {
        val wifiPermissionLine = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            "На Android 13+ приложение также запрашивает доступ к nearby Wi-Fi devices для поиска Wi-Fi точек поблизости."
        } else {
            "Приложение также использует Wi-Fi scan для поиска точек доступа поблизости."
        }

        return "Для более точной проверки приложению нужен доступ к точной геолокации.\n\n" +
            "Он используется для чтения идентификаторов базовых станций и geolocation lookup через BeaconDB.\n\n" +
            wifiPermissionLine + "\n\n" +
            "Без этих разрешений проверка продолжит работать, но часть сигналов местоположения и Wi-Fi scan будут недоступны."
    }

    private fun reRequestPermissions() {
        val missingPermissions = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isEmpty()) {
            Toast.makeText(this, "Все разрешения уже выданы", Toast.LENGTH_SHORT).show()
            return
        }

        val action = PermissionRequestPlanner.decideAction(
            missingPermissions.map { permission ->
                PermissionRequestPlanner.PermissionState(
                    permission = permission,
                    shouldShowRationale = shouldShowRequestPermissionRationale(permission),
                    wasRequestedBefore = hasPermissionBeenRequested(permission),
                )
            },
        )
        when (action) {
            PermissionRequestPlanner.Action.NONE -> Unit
            PermissionRequestPlanner.Action.SHOW_RATIONALE -> {
                showPermissionRationale(missingPermissions.toTypedArray())
            }
            PermissionRequestPlanner.Action.REQUEST -> {
                launchPermissionRequest(missingPermissions.toTypedArray())
            }
            PermissionRequestPlanner.Action.OPEN_SETTINGS -> {
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
    }

    private fun launchPermissionRequest(permissions: Array<String>) {
        if (permissions.isEmpty()) return
        markPermissionsRequested(permissions.asList())
        permissionLauncher.launch(permissions)
    }

    private fun markPermissionsRequested(permissions: Collection<String>) {
        val requested = prefs.getStringSet(PREF_REQUESTED_PERMISSIONS, emptySet())
            ?.toMutableSet()
            ?: mutableSetOf()
        requested.addAll(permissions)
        prefs.edit().putStringSet(PREF_REQUESTED_PERMISSIONS, requested).apply()
    }

    private fun hasPermissionBeenRequested(permission: String): Boolean {
        return prefs.getStringSet(PREF_REQUESTED_PERMISSIONS, emptySet())
            ?.contains(permission) == true
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
        cardIpComparison.visibility = View.GONE
        cardDirect.visibility = View.GONE
        cardIndirect.visibility = View.GONE
        cardLocation.visibility = View.GONE
        cardBypass.visibility = View.GONE
        cardVerdict.visibility = View.GONE
    }

    private fun displayResult(result: CheckResult) {
        displayCategory(result.geoIp, cardGeoIp, iconGeoIp, statusGeoIp, findingsGeoIp)
        displayIpComparison(result.ipComparison)
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

        bindCardStatus(category.detected, category.needsReview, icon, status)

        // GeoIP card: info fields (source==null) go to the key-value section,
        // actual checks (source!=null) go to the findings list
        if (card.id == R.id.cardGeoIp) {
            val infoFindings = category.findings.filter { it.source == null }
            val checkFindings = category.findings.filter { it.source != null }

            geoIpInfoSection.removeAllViews()
            for (finding in infoFindings) {
                val parts = finding.description.split(": ", limit = 2)
                if (parts.size == 2) {
                    geoIpInfoSection.addView(createGeoInfoView(parts[0], parts[1]))
                } else {
                    geoIpInfoSection.addView(createFindingView(finding))
                }
            }
            val hasInfo = infoFindings.isNotEmpty() && checkFindings.isNotEmpty()
            geoIpDivider.visibility = if (hasInfo) View.VISIBLE else View.GONE

            findingsContainer.removeAllViews()
            for (finding in checkFindings) {
                findingsContainer.addView(createFindingView(finding))
            }
            return
        }

        findingsContainer.removeAllViews()
        for (finding in category.findings) {
            if (finding.description.startsWith("network_mcc_ru:")) continue
            findingsContainer.addView(createFindingView(finding))
        }
    }

    private fun displayIpComparison(result: IpComparisonResult) {
        cardIpComparison.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, iconIpComparison, statusIpComparison)
        textIpComparisonSummary.text = result.summary

        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.addView(
            createIpCheckerGroupView(
                group = result.ruGroup,
                expanded = result.detected || result.needsReview || result.ruGroup.needsReview,
            ),
        )
        ipComparisonGroups.addView(
            createIpCheckerGroupView(
                group = result.nonRuGroup,
                expanded = result.detected || result.needsReview || result.nonRuGroup.detected,
            ),
        )
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

    private fun createGeoInfoView(label: String, value: String): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val labelView = TextView(this).apply {
            text = label
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = true
            letterSpacing = 0.05f
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.38f)
        }

        val valueView = TextView(this).apply {
            text = value
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            if (tv.resourceId != 0) {
                setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            } else if (tv.type >= TypedValue.TYPE_FIRST_COLOR_INT && tv.type <= TypedValue.TYPE_LAST_COLOR_INT) {
                setTextColor(tv.data)
            }
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.62f)
        }

        row.addView(labelView)
        row.addView(valueView)
        return row
    }

    private fun createIpCheckerGroupView(
        group: IpCheckerGroupResult,
        expanded: Boolean,
    ): View {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = 8.dp
            }
            radius = 14.dp.toFloat()
            strokeWidth = 1.dp
            strokeColor = ContextCompat.getColor(this@MainActivity, R.color.md_outline_variant)
            setCardBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.md_surface))
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 12.dp, 12.dp, 12.dp)
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val title = TextView(this).apply {
            text = group.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val status = TextView(this).apply {
            text = group.statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, statusColorRes(group.detected, group.needsReview)))
        }

        val toggle = TextView(this).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        val summary = TextView(this).apply {
            text = group.summary
            textSize = 13f
            setPadding(0, 6.dp, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        val details = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (expanded) View.VISIBLE else View.GONE
            setPadding(0, 8.dp, 0, 0)
        }
        group.responses.forEach { response ->
            details.addView(createIpCheckerResponseView(response))
        }

        header.addView(title)
        header.addView(status)
        header.addView(toggle)

        val toggleDetails = {
            val nextExpanded = details.visibility != View.VISIBLE
            details.visibility = if (nextExpanded) View.VISIBLE else View.GONE
            toggle.text = if (nextExpanded) "▼" else "▶"
        }
        header.setOnClickListener { toggleDetails() }
        summary.setOnClickListener { toggleDetails() }

        container.addView(header)
        container.addView(summary)
        container.addView(details)
        card.addView(container)
        return card
    }

    private fun createIpCheckerResponseView(response: IpCheckerResponse): View {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(this).apply {
            text = response.label
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val value = TextView(this).apply {
            text = response.ip ?: "Ошибка"
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    if (response.ip != null) R.color.status_green else R.color.status_amber,
                ),
            )
        }

        val url = TextView(this).apply {
            text = response.url
            textSize = 12f
            setPadding(0, 4.dp, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        topRow.addView(label)
        topRow.addView(value)
        container.addView(topRow)
        container.addView(url)

        if (!response.error.isNullOrBlank()) {
            container.addView(
                TextView(this).apply {
                    text = buildString {
                        if (response.ignoredIpv6Error) {
                            append("IPv6-ошибка проигнорирована: ")
                        }
                        append(response.error)
                    }
                    textSize = 12f
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(
                        ContextCompat.getColor(
                            this@MainActivity,
                            if (response.ignoredIpv6Error) R.color.md_on_surface_variant else R.color.status_amber,
                        ),
                    )
                },
            )
        }

        return container
    }

    private fun displayBypass(bypass: BypassResult) {
        cardBypass.visibility = View.VISIBLE
        textBypassProgress.visibility = View.GONE

        bindCardStatus(bypass.detected, bypass.needsReview, iconBypass, statusBypass)

        findingsBypass.removeAllViews()
        for (finding in bypass.findings) {
            findingsBypass.addView(createFindingView(finding))
        }
    }

    private fun bindCardStatus(
        detected: Boolean,
        needsReview: Boolean,
        icon: ImageView,
        status: TextView,
    ) {
        when {
            detected -> {
                icon.setImageResource(R.drawable.ic_warning)
                status.text = "Обнаружено"
            }
            needsReview -> {
                icon.setImageResource(R.drawable.ic_help)
                status.text = "Требует проверки"
            }
            else -> {
                icon.setImageResource(R.drawable.ic_check_circle)
                status.text = "Чисто"
            }
        }
        status.setTextColor(ContextCompat.getColor(this, statusColorRes(detected, needsReview)))
    }

    private fun statusColorRes(detected: Boolean, needsReview: Boolean): Int {
        return when {
            detected -> R.color.status_red
            needsReview -> R.color.status_amber
            else -> R.color.status_green
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
        private const val PREF_REQUESTED_PERMISSIONS = "requested_permissions"
    }
}
