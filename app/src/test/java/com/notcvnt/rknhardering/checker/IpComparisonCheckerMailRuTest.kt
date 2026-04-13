package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class IpComparisonCheckerMailRuTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `mail ru checker error does not make ru group partial`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "203.0.113.42"),
                response("2ip.ru", IpCheckerScope.RU, error = "HTTP 403"),
                response("mail.ru", IpCheckerScope.RU, error = "HTTP 403"),
                response("ifconfig.me IPv4", IpCheckerScope.NON_RU, ip = "203.0.113.42"),
                response("ipify", IpCheckerScope.NON_RU, ip = "203.0.113.42"),
                response("ip.sb IPv4", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.ruGroup.statusLabel)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.nonRuGroup.statusLabel)
    }

    private fun response(
        label: String,
        scope: IpCheckerScope,
        ip: String? = null,
        error: String? = null,
    ): IpCheckerResponse = IpCheckerResponse(
        label = label,
        url = "https://example.com/$label",
        scope = scope,
        ip = ip,
        error = error,
    )
}
