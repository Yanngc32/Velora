package io.github.yanngc32.velora

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View

/**
 * Draws the trackpad cursor locally, so it follows the finger with no network delay (the host
 * does not include its cursor in the video).
 */
class CursorView(context: Context) : View(context) {
    /** Area of this view showing the remote screen. */
    val videoRect = RectF()
    var cursorX = 0.5f
    var cursorY = 0.5f

    private val density = resources.displayMetrics.density
    private val arrow = Path().apply {
        moveTo(0f, 0f)
        lineTo(0f, 17f)
        lineTo(4.5f, 13f)
        lineTo(7.5f, 19.5f)
        lineTo(10f, 18.5f)
        lineTo(7f, 12f)
        lineTo(12.5f, 12f)
        close()
    }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFFFFFFFF.toInt() }
    private val outline = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFF000000.toInt()
        style = Paint.Style.STROKE
        strokeWidth = 1.2f
        strokeJoin = Paint.Join.ROUND
    }

    override fun onDraw(canvas: Canvas) {
        if (videoRect.isEmpty) return
        canvas.save()
        canvas.translate(videoRect.left + cursorX * videoRect.width(), videoRect.top + cursorY * videoRect.height())
        canvas.scale(density, density)
        canvas.drawPath(arrow, fill)
        canvas.drawPath(arrow, outline)
        canvas.restore()
    }
}
