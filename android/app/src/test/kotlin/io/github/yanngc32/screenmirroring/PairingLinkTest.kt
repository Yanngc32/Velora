package io.github.yanngc32.screenmirroring

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingLinkTest {
    @Test
    fun parsesTheHostQrCode() {
        // As produced by sm_protocol::pairing::pairing_uri.
        val link = PairingLink.parse("screenmirroring://pair?address=%5Bfe80%3A%3A1%5D%3A7420&code=SM1-AbC_d-9")
        assertEquals(PairingLink("[fe80::1]:7420", "SM1-AbC_d-9"), link)
    }

    @Test
    fun rejectsOtherCodes() {
        assertNull(PairingLink.parse("https://example.com"))
        assertNull(PairingLink.parse("screenmirroring://pair?address=1.2.3.4"))
        assertNull(PairingLink.parse("screenmirroring://pair?address=1.2.3.4&code=nope"))
    }
}
