package io.github.yanngc32.velora

import android.content.Context
import android.text.InputType
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager

/** Receives what the soft keyboard produces. */
interface KeyboardSink {
    fun text(text: String)
    fun key(code: Int)
}

/**
 * Invisible view that owns the soft keyboard. Input is forwarded as it is produced instead of
 * being edited locally: the "visible password" input type keeps keyboards from composing or
 * autocorrecting, so each character is committed as it is typed.
 */
class KeyboardInput(context: Context, private val sink: KeyboardSink) : View(context) {
    init {
        isFocusable = true
        isFocusableInTouchMode = true
    }

    override fun onCheckIsTextEditor() = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        outAttrs.inputType = InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN or
            EditorInfo.IME_ACTION_NONE
        return Connection()
    }

    fun toggle() {
        val imm = context.getSystemService(InputMethodManager::class.java) ?: return
        requestFocus()
        if (!imm.isActive(this) || !imm.isAcceptingText) {
            imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
        } else {
            imm.hideSoftInputFromWindow(windowToken, 0)
        }
    }

    private inner class Connection : BaseInputConnection(this@KeyboardInput, false) {
        override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
            if (text.isNotEmpty()) sink.text(text.toString())
            return true
        }

        override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
            repeat(beforeLength.coerceAtMost(64)) { sink.key(Keys.BACKSPACE) }
            repeat(afterLength.coerceAtMost(64)) { sink.key(Keys.DELETE) }
            return true
        }

        override fun sendKeyEvent(event: KeyEvent): Boolean {
            if (event.action != KeyEvent.ACTION_DOWN) return true
            val code = Keys.forAndroidKey(event.keyCode)
            when {
                code != null -> sink.key(code)
                event.unicodeChar != 0 -> sink.text(event.unicodeChar.toChar().toString())
            }
            return true
        }

        override fun performEditorAction(actionCode: Int): Boolean {
            sink.key(Keys.ENTER)
            return true
        }
    }
}
