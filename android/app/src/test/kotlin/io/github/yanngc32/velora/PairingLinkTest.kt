package io.github.yanngc32.velora

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingLinkTest {
    @Test
    fun parsesTheHostQrCode() {
        // As produced by velora_protocol::pairing::pairing_uri.
        val link = PairingLink.parse("velora://pair?address=%5Bfe80%3A%3A1%5D%3A7420&code=VL1-AbC_d-9")
        assertEquals(PairingLink("[fe80::1]:7420", "VL1-AbC_d-9"), link)
    }

    @Test
    fun rejectsOtherCodes() {
        assertNull(PairingLink.parse("https://example.com"))
        assertNull(PairingLink.parse("velora://pair?address=1.2.3.4"))
        assertNull(PairingLink.parse("velora://pair?address=1.2.3.4&code=nope"))
    }
}
