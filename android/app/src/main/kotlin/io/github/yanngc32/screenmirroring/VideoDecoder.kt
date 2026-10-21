package io.github.yanngc32.screenmirroring

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.util.Log
import android.view.Surface
import uniffi.sm_mobile.VideoFrame
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Hardware H.264 decoding straight onto a [Surface] (no copies through the app).
 *
 * Every frame handed in is eventually reported through [Callbacks.done], once rendered or
 * dropped: the host keeps only a few frames in flight, so these acknowledgements are what keep
 * video flowing, and acknowledging on render (not on receipt) keeps the decoder's queue short.
 */
class VideoDecoder(private val surface: Surface, private val callbacks: Callbacks) {
    interface Callbacks {
        fun done(frameId: UInt)
        fun needKeyframe()
    }

    private val queue = LinkedBlockingQueue<VideoFrame>()
    /** Frames inside the codec, in decode order (no B-frames, so output order is the same). */
    private val inCodec = ArrayDeque<UInt>()
    private var codec: MediaCodec? = null
    private var width = 0
    private var height = 0
    @Volatile private var running = true
    private val thread = Thread(::run, "video-decoder").apply { start() }

    /** Called from the network thread. */
    fun submit(frame: VideoFrame) {
        queue.offer(frame)
    }

    fun release() {
        running = false
        thread.join(1000)
    }

    private fun run() {
        try {
            while (running) {
                val frame = queue.poll(4, TimeUnit.MILLISECONDS)
                try {
                    if (frame != null) feed(frame)
                    drain()
                } catch (e: Exception) {
                    // Codec errors (e.g. after the app went to background): start over on a keyframe.
                    Log.w(TAG, "decoder error, resetting", e)
                    reset()
                    callbacks.needKeyframe()
                }
            }
        } finally {
            reset()
            while (true) callbacks.done((queue.poll() ?: break).frameId)
        }
    }

    private fun feed(frame: VideoFrame) {
        val w = frame.width.toInt()
        val h = frame.height.toInt()
        if (codec == null || w != width || h != height) {
            if (!frame.keyframe) {
                // Can't start decoding mid-stream.
                callbacks.done(frame.frameId)
                callbacks.needKeyframe()
                return
            }
            configure(w, h)
        }
        val codec = codec ?: return
        var index: Int
        while (true) {
            index = codec.dequeueInputBuffer(2_000)
            if (index >= 0 || !running) break
            drain() // free output buffers so the codec can accept more input
        }
        if (index < 0) {
            callbacks.done(frame.frameId)
            return
        }
        val buffer = codec.getInputBuffer(index) ?: error("no input buffer")
        buffer.clear()
        buffer.put(frame.data)
        // The frame id travels as the timestamp to match outputs to inputs.
        codec.queueInputBuffer(index, 0, frame.data.size, frame.frameId.toLong(), 0)
        inCodec.addLast(frame.frameId)
    }

    private fun drain() {
        val codec = codec ?: return
        val info = MediaCodec.BufferInfo()
        while (true) {
            val index = codec.dequeueOutputBuffer(info, 0)
            when {
                index >= 0 -> {
                    // Render immediately: no presentation scheduling, lowest latency.
                    codec.releaseOutputBuffer(index, true)
                    val id = info.presentationTimeUs.toUInt()
                    // Frames before this one that never produced output were dropped by the codec.
                    while (inCodec.isNotEmpty()) {
                        val done = inCodec.removeFirst()
                        callbacks.done(done)
                        if (done == id) break
                    }
                }
                index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> continue
                else -> return
            }
        }
    }

    private fun configure(w: Int, h: Int) {
        reset()
        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, w, h).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            setInteger(MediaFormat.KEY_PRIORITY, 0) // realtime
        }
        codec = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC).apply {
            configure(format, surface, null, 0)
            start()
        }
        width = w
        height = h
        Log.i(TAG, "decoding ${w}x$h")
    }

    private fun reset() {
        codec?.let {
            runCatching { it.stop() }
            it.release()
        }
        codec = null
        while (inCodec.isNotEmpty()) callbacks.done(inCodec.removeFirst())
    }

    private companion object {
        const val TAG = "VideoDecoder"
    }
}
