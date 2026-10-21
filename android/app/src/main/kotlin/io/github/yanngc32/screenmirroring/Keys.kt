package io.github.yanngc32.screenmirroring

import android.view.KeyEvent

/** Linux evdev key codes, the protocol's physical-key format. */
object Keys {
    const val ESC = 1
    const val BACKSPACE = 14
    const val TAB = 15
    const val ENTER = 28
    const val LEFT_CTRL = 29
    const val LEFT_SHIFT = 42
    const val LEFT_ALT = 56
    const val LEFT_META = 125
    const val HOME = 102
    const val UP = 103
    const val PAGE_UP = 104
    const val LEFT = 105
    const val RIGHT = 106
    const val END = 107
    const val DOWN = 108
    const val PAGE_DOWN = 109
    const val DELETE = 111

    private const val LETTERS = "qwertyuiop" // evdev 16..25
    private const val LETTERS2 = "asdfghjkl" // 30..38
    private const val LETTERS3 = "zxcvbnm" // 44..50

    /**
     * Physical key for a letter or digit, by its position on a QWERTY keyboard. Used for
     * shortcuts (Ctrl+C) where the host needs a key press, not a character.
     */
    fun forChar(c: Char): Int? {
        val l = c.lowercaseChar()
        LETTERS.indexOf(l).takeIf { it >= 0 }?.let { return 16 + it }
        LETTERS2.indexOf(l).takeIf { it >= 0 }?.let { return 30 + it }
        LETTERS3.indexOf(l).takeIf { it >= 0 }?.let { return 44 + it }
        return when (c) {
            in '1'..'9' -> 2 + (c - '1')
            '0' -> 11
            ' ' -> 57
            else -> null
        }
    }

    /** Android key codes the soft keyboard sends as key events. */
    fun forAndroidKey(keyCode: Int): Int? = when (keyCode) {
        KeyEvent.KEYCODE_DEL -> BACKSPACE
        KeyEvent.KEYCODE_FORWARD_DEL -> DELETE
        KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_NUMPAD_ENTER -> ENTER
        KeyEvent.KEYCODE_TAB -> TAB
        KeyEvent.KEYCODE_ESCAPE -> ESC
        KeyEvent.KEYCODE_DPAD_UP -> UP
        KeyEvent.KEYCODE_DPAD_DOWN -> DOWN
        KeyEvent.KEYCODE_DPAD_LEFT -> LEFT
        KeyEvent.KEYCODE_DPAD_RIGHT -> RIGHT
        KeyEvent.KEYCODE_MOVE_HOME -> HOME
        KeyEvent.KEYCODE_MOVE_END -> END
        KeyEvent.KEYCODE_PAGE_UP -> PAGE_UP
        KeyEvent.KEYCODE_PAGE_DOWN -> PAGE_DOWN
        else -> null
    }
}
