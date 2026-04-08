package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsClassification
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsSignalStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class IndirectSignsCheckerTest {

    @Test
    fun `classifies loopback dns`() {
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("127.0.0.1"))
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("::1"))
    }

    @Test
    fun `classifies private tunnel dns`() {
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("10.0.0.2"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("172.16.0.10"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("fd00::1"))
    }

    @Test
    fun `classifies private lan dns separately`() {
        assertEquals(DnsClassification.PRIVATE_LAN, IndirectSignsChecker.classifyDnsAddress("192.168.1.1"))
    }

    @Test
    fun `classifies known public resolvers`() {
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("1.1.1.1"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("8.8.8.8"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("2606:4700:4700::1111"))
    }

    @Test
    fun `classifies link local and other public dns`() {
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("169.254.1.1"))
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("fe80::1"))
        assertEquals(DnsClassification.OTHER_PUBLIC, IndirectSignsChecker.classifyDnsAddress("77.88.55.55"))
    }

    @Test
    fun `maps public resolvers to clear signal status`() {
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("1.1.1.1"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("8.8.8.8"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("2606:4700:4700::1111"))
    }

    @Test
    fun `maps private tunnel dns to needs review signal status`() {
        assertEquals(DnsSignalStatus.NEEDS_REVIEW, IndirectSignsChecker.classifyDnsSignalStatus("10.0.0.2"))
        assertEquals(DnsSignalStatus.NEEDS_REVIEW, IndirectSignsChecker.classifyDnsSignalStatus("172.16.0.10"))
        assertEquals(DnsSignalStatus.NEEDS_REVIEW, IndirectSignsChecker.classifyDnsSignalStatus("fd00::1"))
    }

    @Test
    fun `maps loopback and local dns to expected signal statuses`() {
        assertEquals(DnsSignalStatus.DETECTED, IndirectSignsChecker.classifyDnsSignalStatus("127.0.0.1"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("192.168.1.1"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("169.254.1.1"))
        assertEquals(DnsSignalStatus.CLEAR, IndirectSignsChecker.classifyDnsSignalStatus("77.88.55.55"))
    }
}
