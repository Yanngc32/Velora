package io.github.yanngc32.velora

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.res.ResourcesCompat
import uniffi.velora_mobile.MobileException
import uniffi.velora_mobile.Session
import uniffi.velora_mobile.SessionListener
import uniffi.velora_mobile.VideoFrame
import kotlin.concurrent.thread
import kotlin.math.min
import uniffi.velora_mobile.Button as RemoteButton

/** Full-screen remote session: video, trackpad, keyboard. */
class SessionActivity : ComponentActivity(), SessionListener, SurfaceHolder.Callback, VideoDecoder.Callbacks {
    private lateinit var videoArea: FrameLayout
    private lateinit var surfaceView: SurfaceView
    private lateinit var cursorView: CursorView
    private lateinit var keyboard: KeyboardInput

    /** "Connecting…" over the video area until the session starts. */
    private var connecting by mutableStateOf(true)
    /** Asking for the computer's password (`true`: the last one was wrong). */
    private var passwordPrompt by mutableStateOf<Boolean?>(null)

    @Volatile private var session: Session? = null
    @Volatile private var decoder: VideoDecoder? = null
    private var videoWidth = 0
    private var videoHeight = 0
    private var finished = false

    /** Modifiers latched from the toolbar, released after the next key. */
    private val latched = linkedSetOf<Int>()
    private val modifierButtons = mutableListOf<Button>()

    private val trackpad = Trackpad(object : PointerSink {
        override fun move(x: Int, y: Int) {
            session?.mouseMove(x.toUShort(), y.toUShort())
            updateCursor()
        }

        override fun button(button: PointerButton, down: Boolean, x: Int, y: Int) {
            val b = if (button == PointerButton.LEFT) RemoteButton.LEFT else RemoteButton.RIGHT
            session?.mouseButton(b, down, x.toUShort(), y.toUShort())
        }

        override fun scroll(dx: Int, dy: Int) {
            session?.scroll(dx.coerceIn(-32768, 32767).toShort(), dy.coerceIn(-32768, 32767).toShort())
        }
    })

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        buildLayout()
        immersive()
        connect()
    }

    /** Full screen; system bars come back with a swipe from the edge. */
    private fun immersive() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 15+ is edge-to-edge for apps targeting it; earlier versions need asking.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                @Suppress("DEPRECATION")
                window.setDecorFitsSystemWindows(false)
            }
            window.insetsController?.apply {
                hide(WindowInsets.Type.systemBars())
                systemBarsBehavior = WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
                View.SYSTEM_UI_FLAG_FULLSCREEN or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        }
    }

    private fun buildLayout() {
        val root = FrameLayout(this).apply { setBackgroundColor(Velora.Bg.toArgb()) }
        videoArea = FrameLayout(this)
        surfaceView = SurfaceView(this).also { it.holder.addCallback(this) }
        cursorView = CursorView(this)
        videoArea.addView(surfaceView, FrameLayout.LayoutParams(1, 1, Gravity.CENTER))
        videoArea.addView(cursorView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        videoArea.setOnTouchListener { _, event -> onTouch(event) }
        videoArea.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> layoutVideo() }

        keyboard = KeyboardInput(this, object : KeyboardSink {
            override fun text(text: String) = typeText(text)
            override fun key(code: Int) = tapKey(code)
        })
        // Status and password prompt, drawn like the rest of the app.
        val overlay = ComposeView(this).apply {
            setContent { VeloraTheme { Overlay() } }
        }

        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(videoArea, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        content.addView(toolbar(), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(content, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        root.addView(keyboard, FrameLayout.LayoutParams(1, 1))
        root.addView(overlay, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        setContentView(root)
    }

    @Composable
    private fun Overlay() {
        if (connecting && passwordPrompt == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(18.dp), color = Velora.AccentText, strokeWidth = 2.dp)
                    Text(stringResource(R.string.connecting), style = MaterialTheme.typography.bodyLarge, color = Velora.Weak)
                }
            }
        }
        passwordPrompt?.let { wrong -> PasswordDialog(wrong) }
    }

    /** The computer has an access password: ask for it and connect again. Never stored. */
    @Composable
    private fun PasswordDialog(wrong: Boolean) {
        var password by remember { mutableStateOf("") }
        val name = intent.getStringExtra(EXTRA_HOST) ?: intent.getStringExtra(EXTRA_ADDRESS) ?: ""
        val submit = {
            passwordPrompt = null
            connect(password)
        }
        VeloraDialog(onDismiss = { finish() }) {
            Text(stringResource(R.string.password_title, name), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(if (wrong) R.string.password_wrong else R.string.password_needed),
                style = MaterialTheme.typography.bodyMedium,
                color = if (wrong) Velora.Error else Velora.Weak,
            )
            Spacer(Modifier.height(16.dp))
            Field(stringResource(R.string.password), password, { password = it }, password = true)
            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SecondaryButton(stringResource(R.string.cancel), { finish() }, Modifier.weight(1f))
                PrimaryButton(stringResource(R.string.connect), submit, Modifier.weight(1f), enabled = password.isNotEmpty())
            }
        }
    }

    private fun toolbar(): View {
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Velora.Card.toArgb())
        }
        val font = ResourcesCompat.getFont(this, R.font.inter_medium)
        fun add(label: String, onClick: (Button) -> Unit) {
            val b = Button(this, null, android.R.attr.borderlessButtonStyle).apply {
                text = label
                typeface = font
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                setTextColor(Velora.Text.toArgb())
                isAllCaps = false
                minWidth = 0
                minimumWidth = 0
                setOnClickListener { onClick(this) }
            }
            bar.addView(b, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        }
        fun modifier(label: String, code: Int) {
            add(label) { b ->
                if (!latched.remove(code)) latched.add(code)
                b.setTextColor(if (code in latched) Velora.AccentText.toArgb() else Velora.Text.toArgb())
            }
            modifierButtons += bar.getChildAt(bar.childCount - 1) as Button
        }
        add("⌨") { keyboard.toggle() }
        add("Esc") { tapKey(Keys.ESC) }
        add("Tab") { tapKey(Keys.TAB) }
        modifier("Ctrl", Keys.LEFT_CTRL)
        modifier("Alt", Keys.LEFT_ALT)
        modifier("Win", Keys.LEFT_META)
        modifier("Shift", Keys.LEFT_SHIFT)
        add("←") { tapKey(Keys.LEFT) }
        add("↑") { tapKey(Keys.UP) }
        add("↓") { tapKey(Keys.DOWN) }
        add("→") { tapKey(Keys.RIGHT) }
        add("Del") { tapKey(Keys.DELETE) }
        add("✕") { finish() }
        // A 1 px line on top, like the cards' borders.
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(View(this@SessionActivity).apply { setBackgroundColor(Velora.Border.toArgb()) }, LinearLayout.LayoutParams(MATCH_PARENT, 1))
            addView(
                HorizontalScrollView(this@SessionActivity).apply {
                    setBackgroundColor(Velora.Card.toArgb())
                    addView(bar)
                },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT),
            )
        }
    }

    /** Connects (or pairs). Called again with the password when the computer asks for one. */
    private fun connect(password: String? = null) {
        val host = intent.getStringExtra(EXTRA_HOST)
        val address = intent.getStringExtra(EXTRA_ADDRESS)
        val code = intent.getStringExtra(EXTRA_CODE)
        thread(name = "connect") {
            try {
                val s = if (host != null) client.connect(host, password) else client.pair(address!!, code!!, password)
                runOnUiThread {
                    if (finished) {
                        s.disconnect()
                        s.close()
                        return@runOnUiThread
                    }
                    session = s
                    connecting = false
                    setVideoSize(s.width().toInt(), s.height().toInt())
                    s.start(this)
                    // What the computer sends meanwhile (Send To there) goes to Downloads.
                    val incoming = IncomingFiles(this, s.hostName())
                    s.receiveFiles(incoming.dir.absolutePath, incoming)
                }
            } catch (e: MobileException.PasswordRequired) {
                runOnUiThread { if (!finished) passwordPrompt = false }
            } catch (e: MobileException.WrongPassword) {
                runOnUiThread { if (!finished) passwordPrompt = true }
            } catch (e: Exception) {
                Log.w(TAG, "connection failed", e)
                runOnUiThread { fail(e.message ?: e.toString()) }
            }
        }
    }


    private fun fail(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    // --- video -------------------------------------------------------------------------------

    override fun onVideoFrame(frame: VideoFrame) {
        if (frame.width.toInt() != videoWidth || frame.height.toInt() != videoHeight) {
            runOnUiThread { setVideoSize(frame.width.toInt(), frame.height.toInt()) }
        }
        val d = decoder
        if (d != null) {
            d.submit(frame)
        } else {
            // No surface (yet): keep the host flowing; a keyframe is requested once it exists.
            session?.frameDone(frame.frameId)
        }
    }

    override fun onClosed(reason: String) {
        runOnUiThread { if (!finished) fail(getString(R.string.disconnected, reason)) }
    }

    override fun done(frameId: UInt) {
        session?.frameDone(frameId)
    }

    override fun needKeyframe() {
        session?.requestKeyframe()
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        decoder = VideoDecoder(holder.surface, this)
        session?.requestKeyframe()
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        decoder?.release()
        decoder = null
    }

    private fun setVideoSize(w: Int, h: Int) {
        videoWidth = w
        videoHeight = h
        layoutVideo()
    }

    /** Fits the video into the available area keeping its aspect ratio. */
    private fun layoutVideo() {
        val areaW = videoArea.width
        val areaH = videoArea.height
        if (videoWidth == 0 || areaW == 0 || areaH == 0) return
        val scale = min(areaW.toFloat() / videoWidth, areaH.toFloat() / videoHeight)
        val w = (videoWidth * scale).toInt()
        val h = (videoHeight * scale).toInt()
        val params = surfaceView.layoutParams as FrameLayout.LayoutParams
        if (params.width != w || params.height != h) {
            params.width = w
            params.height = h
            surfaceView.layoutParams = params
        }
        val left = (areaW - w) / 2f
        val top = (areaH - h) / 2f
        cursorView.videoRect.set(left, top, left + w, top + h)
        trackpad.viewWidth = w.toFloat()
        trackpad.viewHeight = h.toFloat()
        updateCursor()
    }

    private fun updateCursor() {
        cursorView.cursorX = trackpad.cursorX / 65535f
        cursorView.cursorY = trackpad.cursorY / 65535f
        cursorView.invalidate()
    }

    // --- input -------------------------------------------------------------------------------

    private fun onTouch(event: MotionEvent): Boolean {
        val n = event.pointerCount
        var cx = 0f
        var cy = 0f
        for (i in 0 until n) {
            if (event.actionMasked == MotionEvent.ACTION_POINTER_UP && i == event.actionIndex) continue
            cx += event.getX(i)
            cy += event.getY(i)
        }
        val active = if (event.actionMasked == MotionEvent.ACTION_POINTER_UP) n - 1 else n
        cx /= active.coerceAtLeast(1)
        cy /= active.coerceAtLeast(1)
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> trackpad.down(cx, cy)
            MotionEvent.ACTION_POINTER_DOWN -> if (n == 2) trackpad.secondFingerDown(cx, cy) else trackpad.reanchor(cx, cy)
            MotionEvent.ACTION_POINTER_UP -> trackpad.reanchor(cx, cy)
            MotionEvent.ACTION_MOVE -> trackpad.move(cx, cy)
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> trackpad.up()
        }
        return true
    }

    private fun tapKey(code: Int) {
        val s = session ?: return
        for (m in latched) s.key(m.toUShort(), true)
        s.key(code.toUShort(), true)
        s.key(code.toUShort(), false)
        releaseLatched()
    }

    private fun typeText(text: String) {
        // With a modifier latched, letters must be key presses for the shortcut to work.
        if (latched.isNotEmpty() && text.length == 1) {
            Keys.forChar(text[0])?.let { return tapKey(it) }
        }
        session?.text(text)
    }

    private fun releaseLatched() {
        val s = session ?: return
        for (m in latched.reversed()) s.key(m.toUShort(), false)
        latched.clear()
        modifierButtons.forEach { it.setTextColor(Velora.Text.toArgb()) }
    }

    /** Physical keyboards (USB/Bluetooth): Android reports Linux key codes as scan codes. */
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        val s = session
        val physical = event.device?.let { !it.isVirtual && it.supportsSource(InputDevice.SOURCE_KEYBOARD) } ?: false
        if (s != null && physical && event.scanCode in 1..248 && event.keyCode != KeyEvent.KEYCODE_BACK) {
            when (event.action) {
                KeyEvent.ACTION_DOWN -> if (event.repeatCount == 0) s.key(event.scanCode.toUShort(), true)
                KeyEvent.ACTION_UP -> s.key(event.scanCode.toUShort(), false)
            }
            return true
        }
        return super.dispatchKeyEvent(event)
    }

    override fun onPause() {
        super.onPause()
        session?.releaseAll()
        // Sessions don't run in the background: leaving the screen disconnects. Not while
        // asking for the password, though: a password manager's autofill pauses us.
        if (!isChangingConfigurations && passwordPrompt == null) finish()
    }

    override fun finish() {
        finished = true
        super.finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        decoder?.release()
        decoder = null
        session?.let {
            it.disconnect()
            it.close()
        }
        session = null
    }

    companion object {
        private const val TAG = "SessionActivity"
        private const val EXTRA_HOST = "host"
        private const val EXTRA_ADDRESS = "address"
        private const val EXTRA_CODE = "code"

        fun connect(context: Context, host: String) =
            context.startActivity(Intent(context, SessionActivity::class.java).putExtra(EXTRA_HOST, host))

        fun pair(context: Context, address: String, code: String) = context.startActivity(
            Intent(context, SessionActivity::class.java).putExtra(EXTRA_ADDRESS, address).putExtra(EXTRA_CODE, code)
        )
    }
}
