package io.github.yanngc32.velora

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.widget.Toast
import androidx.core.content.IntentCompat
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject

/**
 * Updates from GitHub Releases, like the desktop app: the latest release's
 * `velora-<version>-android.apk`. Android installs it only over an app signed with the same
 * key, and always asks the user to confirm. Debug builds are signed with another key and never
 * update.
 */
object Updater {
    private const val LATEST = "https://api.github.com/repos/Yanngc32/Velora/releases/latest"
    private const val TIMEOUT_MS = 15_000

    data class Update(val version: String, val url: String, val size: Long)

    /** The latest release when it is newer than this app. Blocking. */
    fun check(): Update? {
        if (BuildConfig.DEBUG) return null
        val release = open(LATEST, "application/vnd.github+json").use { JSONObject(it.readBytes().decodeToString()) }
        val version = release.getString("tag_name").removePrefix("v")
        if (!isNewer(version, BuildConfig.VERSION_NAME)) return null
        val assets = release.getJSONArray("assets")
        val name = "velora-$version-android.apk"
        for (i in 0 until assets.length()) {
            val asset = assets.getJSONObject(i)
            if (asset.getString("name") == name) {
                return Update(version, asset.getString("browser_download_url"), asset.getLong("size"))
            }
        }
        return null
    }

    /** Compares `major.minor.patch`, ignoring any pre-release suffix. */
    fun isNewer(candidate: String, current: String): Boolean {
        fun parts(v: String) = v.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        val a = parts(candidate)
        val b = parts(current)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    /**
     * Downloads the update into an installer session and commits it; [UpdateReceiver] then asks
     * the user to confirm. Blocking. `onProgress` gets 0..1.
     */
    fun install(context: Context, update: Update, onProgress: (Float) -> Unit) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(update.size)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            try {
                open(update.url, "application/octet-stream").use { input ->
                    session.openWrite("velora.apk", 0, update.size).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var done = 0L
                        while (true) {
                            val n = input.read(buffer)
                            if (n < 0) break
                            output.write(buffer, 0, n)
                            done += n
                            onProgress((done.toFloat() / update.size).coerceIn(0f, 1f))
                        }
                        session.fsync(output)
                    }
                }
                // Mutable: the installer adds the status and the confirmation intent.
                val status = PendingIntent.getBroadcast(
                    context,
                    id,
                    Intent(context, UpdateReceiver::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
                session.commit(status.intentSender)
            } catch (e: Exception) {
                session.abandon()
                throw e
            }
        }
    }

    /** HTTPS only; GitHub's download links redirect to another HTTPS host, which is followed. */
    private fun open(url: String, accept: String) = (URL(url).openConnection() as HttpsURLConnection).run {
        connectTimeout = TIMEOUT_MS
        readTimeout = TIMEOUT_MS
        setRequestProperty("Accept", accept)
        inputStream
    }
}

/** The installer's answer: show its confirmation screen, or say why it failed. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java) ?: return
                context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            // The new version replaces this process.
            PackageInstaller.STATUS_SUCCESS -> Unit
            else -> {
                val reason = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
                Toast.makeText(context, context.getString(R.string.update_failed, reason), Toast.LENGTH_LONG).show()
            }
        }
    }
}
