package io.github.yanngc32.velora

import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.min
import kotlin.math.roundToInt

/** Where trackpad gestures end up; implemented over the session. */
interface PointerSink {
    /** Absolute position, 0..65535 on each axis of the remote display. */
    fun move(x: Int, y: Int)
    fun button(button: PointerButton, down: Boolean, x: Int, y: Int)
    /** Wheel units (120 per notch); positive dy scrolls up. */
    fun scroll(dx: Int, dy: Int)
    /**
     * Two fingers spread or pinched: zoom the view [scale] times around [focusX]/[focusY]
     * (view pixels) and move it by [dx]/[dy] with the fingers.
     */
    fun pinch(scale: Float, focusX: Float, focusY: Float, dx: Float, dy: Float) {}
}

enum class PointerButton { LEFT, RIGHT }

/**
 * Turns touches into a laptop-style trackpad, independent of Android so it can be unit tested:
 * - one finger moves the cursor (relative, with acceleration);
 * - tap clicks; tap then drag holds the button (drag and drop);
 * - two-finger tap right-clicks; two-finger drag scrolls (natural direction);
 * - two fingers spreading or pinching zoom the view (the remote computer sees nothing).
 *
 * Coordinates are view pixels; [viewWidth]/[viewHeight] is the area showing the remote screen.
 */
class Trackpad(private val sink: PointerSink, private val clock: () -> Long = System::currentTimeMillis) {
    var viewWidth = 1f
    var viewHeight = 1f

    /** Cursor position on the remote display, 0..65535. Drawn locally for instant feedback. */
    var cursorX = 32768f
        private set
    var cursorY = 32768f
        private set

    private var mode = Mode.IDLE
    private var downTime = 0L
    private var downX = 0f
    private var downY = 0f
    private var lastX = 0f
    private var lastY = 0f
    private var lastMoveTime = 0L
    private var maxPointers = 0
    private var moved = false
    private var lastTapUp = -1L
    private var scrollRemainderX = 0f
    private var scrollRemainderY = 0f
    /** Distance between the fingers when two touched, and at the last move. */
    private var startSpan = 0f
    private var lastSpan = 0f

    /** TWO: two fingers down, not yet told whether they scroll or zoom. */
    private enum class Mode { IDLE, MOVE, DRAG, TWO, SCROLL, PINCH }

    fun down(x: Float, y: Float) {
        val now = clock()
        // A touch right after a tap starts a drag: the button is held until the finger lifts.
        mode = if (lastTapUp >= 0 && now - lastTapUp < DOUBLE_TAP_MS) {
            sink.button(PointerButton.LEFT, true, cx(), cy())
            Mode.DRAG
        } else {
            Mode.MOVE
        }
        downTime = now
        downX = x; downY = y
        lastX = x; lastY = y
        lastMoveTime = now
        maxPointers = 1
        moved = false
    }

    /**
     * A second finger touched: scroll or zoom, as the fingers go on to tell. [x]/[y] is the
     * fingers' centroid, [span] the distance between them.
     */
    fun secondFingerDown(x: Float, y: Float, span: Float = 0f) {
        maxPointers = 2
        if (mode == Mode.DRAG) return
        mode = Mode.TWO
        lastX = x; lastY = y
        startSpan = span; lastSpan = span
    }

    /** Fingers were added or lifted mid-gesture: continue from [x]/[y] and [span] without a jump. */
    fun reanchor(x: Float, y: Float, span: Float = 0f) {
        lastX = x; lastY = y
        startSpan = span; lastSpan = span
    }

    fun move(x: Float, y: Float, span: Float = 0f) {
        val now = clock()
        val dx = x - lastX
        val dy = y - lastY
        if (!moved && hypot(x - downX, y - downY) > TOUCH_SLOP_PX) moved = true
        if (mode == Mode.TWO) {
            // Fingers moving apart or together zoom; moving along together, they scroll. Until
            // one is clear, nothing happens and the travel so far counts for whichever wins.
            when {
                startSpan > 0f && span > 0f && abs(span - startSpan) > PINCH_SLOP_PX -> {
                    // Zooming starts from here, without a jump by the slop.
                    mode = Mode.PINCH
                    moved = true
                    lastSpan = span
                    lastX = x; lastY = y
                    return
                }
                hypot(dx, dy) > TOUCH_SLOP_PX -> mode = Mode.SCROLL
                else -> return
            }
        }
        when (mode) {
            Mode.MOVE, Mode.DRAG -> {
                val dt = (now - lastMoveTime).coerceAtLeast(1)
                val speed = hypot(dx, dy) / dt // px per ms
                val gain = BASE_GAIN * min(1f + speed * ACCELERATION, MAX_ACCELERATION)
                cursorX = (cursorX + dx / viewWidth * 65535f * gain).coerceIn(0f, 65535f)
                cursorY = (cursorY + dy / viewHeight * 65535f * gain).coerceIn(0f, 65535f)
                sink.move(cx(), cy())
            }
            Mode.SCROLL -> {
                // Natural scrolling: content follows the fingers.
                scrollRemainderX += -dx * WHEEL_UNITS_PER_PX
                scrollRemainderY += dy * WHEEL_UNITS_PER_PX
                val sx = scrollRemainderX.toInt()
                val sy = scrollRemainderY.toInt()
                if (abs(sx) >= MIN_SCROLL || abs(sy) >= MIN_SCROLL) {
                    scrollRemainderX -= sx
                    scrollRemainderY -= sy
                    sink.scroll(sx, sy)
                }
            }
            Mode.PINCH -> {
                val scale = if (lastSpan > 0f && span > 0f) span / lastSpan else 1f
                sink.pinch(scale, x, y, x - lastX, y - lastY)
                lastSpan = span
            }
            Mode.IDLE, Mode.TWO -> {}
        }
        lastX = x; lastY = y
        lastMoveTime = now
    }

    fun up() {
        val now = clock()
        val tap = !moved && now - downTime < TAP_MS
        when {
            mode == Mode.DRAG -> {
                sink.button(PointerButton.LEFT, false, cx(), cy())
                lastTapUp = -1
            }
            tap && maxPointers >= 2 -> click(PointerButton.RIGHT).also { lastTapUp = -1 }
            tap -> click(PointerButton.LEFT).also { lastTapUp = now }
            else -> lastTapUp = -1
        }
        mode = Mode.IDLE
        scrollRemainderX = 0f
        scrollRemainderY = 0f
    }

    private fun click(button: PointerButton) {
        sink.button(button, true, cx(), cy())
        sink.button(button, false, cx(), cy())
    }

    private fun cx() = cursorX.roundToInt()
    private fun cy() = cursorY.roundToInt()

    companion object {
        const val TAP_MS = 200L
        const val DOUBLE_TAP_MS = 300L
        const val TOUCH_SLOP_PX = 12f
        /** A swipe across the whole view moves the cursor across the whole remote screen. */
        const val BASE_GAIN = 1f
        const val ACCELERATION = 0.8f
        const val MAX_ACCELERATION = 3f
        /** 120 wheel units (one notch) per 40 px of finger travel. */
        const val WHEEL_UNITS_PER_PX = 3f
        const val MIN_SCROLL = 10
        /** How much the fingers must spread or close before it counts as zooming. */
        const val PINCH_SLOP_PX = 40f
    }
}
