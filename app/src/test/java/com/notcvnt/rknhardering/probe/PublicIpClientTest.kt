package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PublicIpClientTest {

    @Test
    fun `extractIp strips quotes from quoted plain response`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("\"1.2.3.4\""))
    }

    @Test
    fun `extractIp keeps plain ipv6 response`() {
        assertEquals("2001:db8::1", PublicIpClient.extractIp("2001:db8::1"))
    }

    @Test
    fun `extractIp parses json ip field`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("{\"ip\":\"1.2.3.4\"}"))
    }

    @Test
    fun `extractIp parses json ip field with spaces`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("{\"ip\": \"1.2.3.4\", \"city\": {}}"))
    }

    @Test
    fun `extractIp rejects non ip json`() {
        assertNull(PublicIpClient.extractIp("{\"country\":\"RU\",\"city\":\"Moscow\"}"))
    }

    @Test
    fun `extractIp extracts ip from ip mail ru html`() {
        val html = """
            <!DOCTYPE html><html><head><title>IP</title></head>
            <body><div class="content"><span>IP:</span><strong>1.2.3.4</strong></div></body></html>
        """.trimIndent()
        assertEquals("1.2.3.4", PublicIpClient.extractIp(html, endpoint = "https://ip.mail.ru"))
    }

    @Test
    fun `extractIp rejects incidental ipv4 from html`() {
        val html = """
            <!DOCTYPE html><html><head><title>Error</title></head>
            <body><div>Gateway timeout from 5.6.7.8</div></body></html>
        """.trimIndent()
        assertNull(PublicIpClient.extractIp(html, endpoint = "https://ip.mail.ru"))
    }

    @Test
    fun `formatHttpError keeps html 403 concise`() {
        val html = """
            <!DOCTYPE html>
            <html><body>Forbidden</body></html>
        """.trimIndent()

        assertEquals("HTTP 403", PublicIpClient.formatHttpError(403, html))
    }
}
