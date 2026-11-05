package io.github.yanngc32.velora

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackpadTest {
    private val events = mutableListOf<String>()
    private var now = 0L
    private val sink = object : PointerSink {
        override fun move(x: Int, y: Int) { events += "move" }
        override fun button(button: PointerButton, down: Boolean, x: Int, y: Int) {
            events += "${button.name.lowercase()}${if (down) "Down" else "Up"}"
        }
        override fun scroll(dx: Int, dy: Int) { events += "scroll($dx,$dy)" }
        override fun pinch(scale: Float, focusX: Float, focusY: Float, dx: Float, dy: Float) {
            events += "pinch(${"%.2f".format(java.util.Locale.ROOT, scale)},${dx.toInt()},${dy.toInt()})"
        }
    }
    private val pad = Trackpad(sink) { now }.apply { viewWidth = 1000f; viewHeight = 500f }

    @Test
    fun tapClicks() {
        pad.down(100f, 100f); now += 50; pad.up()
        assertEquals(listOf("leftDown", "leftUp"), events)
    }

    @Test
    fun dragMovesCursorWithoutClicking() {
        pad.down(100f, 100f)
        now += 100; pad.move(200f, 100f)
        now += 100; pad.up()
        assertEquals(listOf("move"), events)
        assertTrue("cursor moved right", pad.cursorX > 32768f)
        assertEquals(32768f, pad.cursorY, 0.01f)
    }

    @Test
    fun cursorStaysOnScreen() {
        pad.down(0f, 0f)
        now += 1; pad.move(-100000f, -100000f)
        assertEquals(0f, pad.cursorX, 0f)
        assertEquals(0f, pad.cursorY, 0f)
    }

    @Test
    fun tapThenDragHoldsTheButton() {
        pad.down(100f, 100f); now += 50; pad.up()
        now += 100; pad.down(100f, 100f)
        now += 50; pad.move(150f, 100f)
        now += 50; pad.up()
        assertEquals(listOf("leftDown", "leftUp", "leftDown", "move", "leftUp"), events)
    }

    @Test
    fun twoFingerTapRightClicks() {
        pad.down(100f, 100f); pad.secondFingerDown(120f, 100f); now += 80; pad.up()
        assertEquals(listOf("rightDown", "rightUp"), events)
    }

    @Test
    fun twoFingerDragScrollsNaturally() {
        pad.down(100f, 300f); pad.secondFingerDown(100f, 300f)
        now += 16; pad.move(100f, 260f) // fingers move up: content scrolls down (wheel down)
        now += 16; pad.up()
        assertEquals(listOf("scroll(0,-120)"), events)
    }

    @Test
    fun liftingOneOfTwoFingersDoesNotJump() {
        pad.down(100f, 300f); pad.secondFingerDown(150f, 300f)
        pad.reanchor(100f, 300f) // second finger lifted: centroid is back on the first finger
        now += 16; pad.move(100f, 300f)
        now += 300; pad.up() // held too long to count as a two-finger tap
        assertTrue("no scroll from the centroid jump", events.isEmpty())
    }

    @Test
    fun slowTapIsNotAClick() {
        pad.down(100f, 100f); now += 500; pad.up()
        assertTrue(events.isEmpty())
    }

    @Test
    fun spreadingTwoFingersZoomsWithoutScrollingOrClicking() {
        pad.down(100f, 300f); pad.secondFingerDown(150f, 300f, span = 100f)
        now += 16; pad.move(150f, 300f, span = 150f) // past the slop: zooming starts here
        now += 16; pad.move(160f, 300f, span = 300f) // twice as far apart, and 10 px right
        now += 16; pad.up()
        assertEquals(listOf("pinch(2.00,10,0)"), events)
    }

    @Test
    fun twoFingersMovingTogetherStillScroll() {
        pad.down(100f, 300f); pad.secondFingerDown(125f, 300f, span = 50f)
        now += 16; pad.move(125f, 260f, span = 55f)
        now += 16; pad.up()
        assertEquals(listOf("scroll(0,-120)"), events)
    }
}
