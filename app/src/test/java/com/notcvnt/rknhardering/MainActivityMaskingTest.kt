package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class MainActivityMaskingTest {

    @Test
    fun `maskInfoValue masks any ip-like value in privacy mode`() {
        val masked = maskInfoValue("203.0.113.64 via 198.51.100.25", privacyMode = true)

        assertEquals("203.0.*.* via 198.51.*.*", masked)
        assertFalse(masked.contains("203.0.113.64"))
        assertFalse(masked.contains("198.51.100.25"))
    }

    @Test
    fun `maskInfoValue leaves value unchanged when privacy mode is off`() {
        assertEquals("203.0.113.64", maskInfoValue("203.0.113.64", privacyMode = false))
    }
}
