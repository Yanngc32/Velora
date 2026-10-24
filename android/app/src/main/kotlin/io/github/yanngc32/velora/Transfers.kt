package io.github.yanngc32.velora

import android.Manifest
import android.annotation.TargetApi
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import android.widget.Toast
import java.io.File
import java.io.IOException
import java.util.Collections
import kotlin.concurrent.thread
import uniffi.velora_mobile.OfferListener
import uniffi.velora_mobile.TransferListener

/** Moving files between the app's private staging folders and the rest of the phone. */
object Transfers {
    /** A fresh, empty staging folder under the app's cache, e.g. for one upload. */
    fun stagingDir(context: Context, kind: String): File {
        val dir = File(File(context.cacheDir, kind), System.nanoTime().toString())
        dir.mkdirs()
        return dir
    }

    /**
     * Copies shared or picked documents into `dir` under their display names, so the Rust side
     * can read them as plain files. Returns the copies' absolute paths.
     */
    fun copyIn(context: Context, uris: List<Uri>, dir: File): List<String> {
        val resolver = context.contentResolver
        return uris.map { uri ->
            val target = unique(dir, safeName(displayName(context, uri)))
            val input = resolver.openInputStream(uri) ?: throw IOException("cannot read $uri")
            input.use { inp -> target.outputStream().use { inp.copyTo(it) } }
            target.absolutePath
        }
    }

    /** Writes shared text (no file attached) into `dir` as a .txt file. */
    fun textFile(dir: File, name: String, text: String): String {
        val target = unique(dir, safeName(name))
        target.writeText(text)
        return target.absolutePath
    }

    private fun displayName(context: Context, uri: Uri): String {
        val fromProvider = runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null
            }
        }.getOrNull()
        return fromProvider ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
    }

    /** No path separators or characters Windows refuses in a name. */
    private fun safeName(name: String): String {
        val cleaned = name.replace(Regex("""[\\/:*?"<>|\u0000-\u001f]"""), "_").trim().trimEnd('.')
        return cleaned.ifEmpty { "file" }
    }

    /** `name` inside `dir`, or `name (1)`, `name (2)`… when it is taken, like the computer does. */
    private fun unique(dir: File, name: String): File {
        var candidate = File(dir, name)
        if (!candidate.exists()) return candidate
        val dot = name.lastIndexOf('.').takeIf { it > 0 } ?: name.length
        val (stem, ext) = name.substring(0, dot) to name.substring(dot)
        var n = 1
        while (candidate.exists()) candidate = File(dir, "$stem ($n)$ext").also { n++ }
        return candidate
    }

    /**
     * Moves `staged` (a file or a folder) into the phone's public Downloads folder and deletes
     * it from staging. Returns how it is called there.
     */
    fun publish(context: Context, staged: File): String {
        try {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                publishTree(context, staged, Environment.DIRECTORY_DOWNLOADS)
            } else {
                val target = unique(legacyDownloads(context), staged.name)
                staged.copyRecursively(target)
                val paths = target.walkTopDown().filter { it.isFile }.map { it.absolutePath }.toList().toTypedArray()
                MediaScannerConnection.scanFile(context, paths, null, null)
                target.name
            }
        } finally {
            staged.deleteRecursively()
        }
    }

    @TargetApi(Build.VERSION_CODES.Q)
    /** Returns the name the file got there: MediaStore renames one whose name is taken ("x (1).pdf"). */
    private fun publishTree(context: Context, file: File, relativeDir: String): String {
        if (file.isDirectory) {
            file.listFiles()?.forEach { publishTree(context, it, "$relativeDir/${file.name}") }
            return file.name
        }
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, file.name)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType(file.name))
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativeDir)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IOException("cannot create ${file.name} in Downloads")
        try {
            val out = resolver.openOutputStream(uri) ?: throw IOException("cannot write ${file.name}")
            out.use { o -> file.inputStream().use { it.copyTo(o) } }
            values.clear()
            values.put(MediaStore.MediaColumns.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)
            throw e
        }
        val given = runCatching {
            resolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        }.getOrNull()
        return given ?: file.name
    }

    /**
     * Android 8–9: the public Downloads folder needs the storage permission (asked on the
     * device list); without it, the app's own Downloads folder on the shared storage.
     */
    private fun legacyDownloads(context: Context): File {
        val public = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val dir = if (hasLegacyStorage(context)) public else context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: public
        dir.mkdirs()
        return dir
    }

    fun needsLegacyPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q && !hasLegacyStorage(context)

    private fun hasLegacyStorage(context: Context): Boolean =
        context.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun mimeType(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }

    /** "1.5 MB", for progress and listings. */
    fun size(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = bytes / 1024.0
        var unit = 0
        while (value >= 1024 && unit < units.size - 1) {
            value /= 1024
            unit++
        }
        return if (value >= 100) "%.0f %s".format(value, units[unit]) else "%.1f %s".format(value, units[unit])
    }
}

/** Progress of one transfer as a fraction, on whatever thread Rust calls from. */
class ProgressListener(private val onFraction: (Float) -> Unit) : TransferListener {
    override fun onProgress(done: ULong, total: ULong) {
        onFraction(if (total == 0UL) 1f else (done.toDouble() / total.toDouble()).toFloat())
    }
}

/**
 * Files the computer sends during a session (Send To, Velora there): they land in a staging
 * folder, then move to the phone's public Downloads, with a toast for each step.
 */
class IncomingFiles(context: Context, private val host: String) : OfferListener {
    private val context = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val announced = Collections.synchronizedSet(mutableSetOf<ULong>())

    /** Where the Rust side saves them; one session at a time, so leftovers can go. */
    val dir: File = File(context.cacheDir, "incoming").also {
        it.deleteRecursively()
        it.mkdirs()
    }

    override fun onOfferProgress(id: ULong, done: ULong, total: ULong) {
        if (announced.add(id)) toast(context.getString(R.string.receiving_from, host))
    }

    override fun onOfferSaved(id: ULong, names: List<String>) {
        announced.remove(id)
        // Called on a network thread: copying out of it would hold up the session.
        thread(name = "publish") {
            runCatching { names.map { Transfers.publish(context, File(dir, it)) } }
                .onSuccess { toast(context.getString(R.string.saved_to_downloads, it.joinToString(", "))) }
                .onFailure { toast(context.getString(R.string.receive_failed, it.message ?: it.toString())) }
        }
    }

    override fun onOfferFailed(id: ULong, error: String) {
        announced.remove(id)
        toast(context.getString(R.string.receive_failed, error))
    }

    private fun toast(message: String) {
        main.post { Toast.makeText(context, message, Toast.LENGTH_LONG).show() }
    }
}
