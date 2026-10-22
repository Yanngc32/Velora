package io.github.yanngc32.velora

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdaterTest {
    @Test
    fun comparesVersionsNumerically() {
        assertTrue(Updater.isNewer("0.3.0", "0.2.0"))
        assertTrue(Updater.isNewer("0.10.0", "0.9.9"))
        assertTrue(Updater.isNewer("1.0.0", "0.99.99"))
        assertFalse(Updater.isNewer("0.2.0", "0.2.0"))
        assertFalse(Updater.isNewer("0.1.9", "0.2.0"))
    }

    @Test
    fun ignoresPreReleaseSuffixes() {
        assertFalse(Updater.isNewer("0.2.0-beta", "0.2.0"))
        assertTrue(Updater.isNewer("0.3.0-rc1", "0.2.0"))
    }
}
