package io.github.yanngc32.velora

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.concurrent.thread
import uniffi.velora_mobile.Files
import uniffi.velora_mobile.HostEntry
import uniffi.velora_mobile.MobileException

/**
 * Android's share sheet → Velora: pick a paired computer and the shared files go into its
 * Downloads folder, over a files-only connection (a session someone has with it carries on).
 */
class ShareActivity : ComponentActivity() {
    private sealed interface Step {
        data object Pick : Step
        /** `progress`: null while connecting, 0 while the computer's user is asked. */
        data class Sending(val host: String, val progress: Float?) : Step
        data class Sent(val host: String, val names: List<String>) : Step
        data class Failed(val host: String, val message: String) : Step
    }

    private val hosts = mutableStateListOf<HostEntry>()
    private var step by mutableStateOf<Step>(Step.Pick)
    /** Host asking for its password, and whether the last one was wrong. */
    private var passwordPrompt by mutableStateOf<Pair<String, Boolean>?>(null)

    private var uris: List<Uri> = emptyList()
    private var text: String? = null

    @Volatile private var files: Files? = null
    @Volatile private var finished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        uris = sharedUris(intent)
        text = if (uris.isEmpty()) intent.getStringExtra(Intent.EXTRA_TEXT)?.takeIf { it.isNotBlank() } else null
        runCatching { client.hosts() }.onSuccess { hosts.addAll(it) }.onFailure { Log.w(TAG, "no hosts", it) }
        setContent {
            VeloraTheme {
                Box(Modifier.fillMaxSize().background(Velora.Bg)) {
                    Screen()
                    passwordPrompt?.let { (host, wrong) ->
                        PasswordPrompt(
                            host,
                            wrong,
                            onSubmit = { passwordPrompt = null; send(host, it) },
                            onCancel = { passwordPrompt = null },
                        )
                    }
                }
            }
        }
    }

    private fun itemCount(): Int = if (text != null) 1 else uris.size

    private fun send(host: String, password: String?) {
        if (step is Step.Sending) return
        step = Step.Sending(host, null)
        thread(name = "share") {
            val staging = Transfers.stagingDir(this, "outgoing")
            try {
                val paths = text?.let { listOf(Transfers.textFile(staging, getString(R.string.shared_text_name), it)) }
                    ?: Transfers.copyIn(this, uris, staging)
                val f = client.openFiles(host, password)
                files = f
                try {
                    if (finished) return@thread
                    runOnUiThread { step = Step.Sending(host, 0f) }
                    val names = f.upload(paths, "", ProgressListener { p ->
                        runOnUiThread { if (step is Step.Sending) step = Step.Sending(host, p) }
                    })
                    runOnUiThread { step = Step.Sent(host, names) }
                } finally {
                    files = null
                    f.disconnect()
                    f.close()
                }
            } catch (e: MobileException.PasswordRequired) {
                runOnUiThread { step = Step.Pick; passwordPrompt = host to false }
            } catch (e: MobileException.WrongPassword) {
                runOnUiThread { step = Step.Pick; passwordPrompt = host to true }
            } catch (e: Exception) {
                Log.w(TAG, "sharing failed", e)
                runOnUiThread { step = Step.Failed(host, e.message ?: e.toString()) }
            } finally {
                staging.deleteRecursively()
            }
        }
    }

    @Composable
    private fun Screen() {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 20.dp, vertical = 16.dp)) {
            val count = itemCount()
            PageHeader(
                stringResource(R.string.app_name),
                stringResource(R.string.share_title),
                if (count > 0) pluralStringResource(R.plurals.share_items, count, count) else null,
            )
            Spacer(Modifier.height(20.dp))
            Box(Modifier.weight(1f)) {
                when (val s = step) {
                    Step.Pick -> when {
                        count == 0 -> Message(stringResource(R.string.share_nothing))
                        hosts.isEmpty() -> Message(stringResource(R.string.share_no_hosts))
                        else -> HostList { send(it.name, null) }
                    }
                    is Step.Sending -> TransferStatus(s.host, s.progress)
                    is Step.Sent -> Message(stringResource(R.string.sent_to_downloads, s.host) + "\n" + s.names.joinToString("\n"))
                    is Step.Failed -> Message(stringResource(R.string.send_failed, s.message), error = true)
                }
            }
            Spacer(Modifier.height(16.dp))
            when (val s = step) {
                is Step.Failed -> Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton(stringResource(R.string.cancel), { finish() }, Modifier.weight(1f))
                    PrimaryButton(stringResource(R.string.try_again), { step = Step.Pick; send(s.host, null) }, Modifier.weight(1f))
                }
                is Step.Sent -> PrimaryButton(stringResource(R.string.done), { finish() }, Modifier.fillMaxWidth())
                else -> SecondaryButton(stringResource(R.string.cancel), { finish() }, Modifier.fillMaxWidth())
            }
        }
    }

    @Composable
    private fun Message(text: String, error: Boolean = false) {
        VeloraCard(padding = PaddingValues(20.dp)) {
            Text(text, style = MaterialTheme.typography.bodyMedium, color = if (error) Velora.Error else Velora.Weak)
        }
    }

    @Composable
    private fun HostList(onPick: (HostEntry) -> Unit) {
        VeloraCard(padding = PaddingValues(0.dp)) {
            LazyColumn {
                itemsIndexed(hosts) { i, host ->
                    if (i > 0) HorizontalDivider(color = Velora.Border, thickness = 1.dp)
                    Row(
                        Modifier.fillMaxWidth().clickable { onPick(host) }.padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        IconTile(R.drawable.ic_monitor)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(host.name, style = MaterialTheme.typography.titleSmall.copy(fontSize = 15.sp))
                            Text(host.address, style = TextStyle(fontFamily = Velora.Mono, fontSize = 12.sp, color = Velora.Weak))
                        }
                    }
                }
            }
        }
    }

    override fun finish() {
        finished = true
        super.finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        finished = true
        // Leaving stops a transfer under way.
        files?.disconnect()
    }

    companion object {
        private const val TAG = "ShareActivity"

        /** The files of an ACTION_SEND or ACTION_SEND_MULTIPLE, whichever way the app put them. */
        private fun sharedUris(intent: Intent): List<Uri> {
            val out = mutableListOf<Uri>()
            when (intent.action) {
                Intent.ACTION_SEND -> {
                    val uri: Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(Intent.EXTRA_STREAM)
                    }
                    uri?.let(out::add)
                }
                Intent.ACTION_SEND_MULTIPLE -> {
                    val list: ArrayList<Uri>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                    }
                    list?.let(out::addAll)
                }
            }
            if (out.isEmpty()) {
                intent.clipData?.let { clip -> for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let(out::add) }
            }
            return out.distinct()
        }
    }
}
