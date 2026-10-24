package io.github.yanngc32.velora

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File
import kotlin.concurrent.thread
import uniffi.velora_mobile.FileEntry
import uniffi.velora_mobile.FileKind
import uniffi.velora_mobile.Files
import uniffi.velora_mobile.MobileException

/**
 * A paired computer's files, over a files-only connection (a session someone has with it
 * carries on): browse its drives and folders, download to the phone's Downloads, upload
 * documents picked on the phone into the folder shown.
 */
class FilesActivity : ComponentActivity() {
    private val host: String get() = intent.getStringExtra(EXTRA_HOST) ?: ""

    @Volatile private var files: Files? = null
    @Volatile private var finished = false

    /** Folders opened from the roots, last one shown; empty: the roots. */
    private val stack = mutableStateListOf<FileEntry>()
    private val entries = mutableStateListOf<FileEntry>()
    private var loading by mutableStateOf(true)
    private var error by mutableStateOf<String?>(null)
    /** Asking for the computer's password (`true`: the last one was wrong). */
    private var passwordPrompt by mutableStateOf<Boolean?>(null)
    /** The transfer under way (one at a time), with its progress (null: not started yet). */
    private var transfer by mutableStateOf<Pair<String, Float?>?>(null)
    /** Bumped on every listing, so a slow answer for a folder already left is dropped. */
    private var generation = 0

    private val pick = registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) upload(uris)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            VeloraTheme {
                Box(Modifier.fillMaxSize().background(Velora.Bg)) {
                    BackHandler(enabled = stack.isNotEmpty()) { up() }
                    Screen()
                    passwordPrompt?.let { wrong ->
                        PasswordPrompt(host, wrong, onSubmit = { passwordPrompt = null; connect(it) }, onCancel = { finish() })
                    }
                }
            }
        }
        connect(null)
    }

    private fun connect(password: String?) {
        loading = true
        thread(name = "files-connect") {
            try {
                val f = client.openFiles(host, password)
                runOnUiThread {
                    if (finished) {
                        f.disconnect()
                        f.close()
                    } else {
                        files = f
                        load()
                    }
                }
            } catch (e: MobileException.PasswordRequired) {
                runOnUiThread { if (!finished) passwordPrompt = false }
            } catch (e: MobileException.WrongPassword) {
                runOnUiThread { if (!finished) passwordPrompt = true }
            } catch (e: Exception) {
                Log.w(TAG, "connection failed", e)
                runOnUiThread {
                    if (!finished) {
                        Toast.makeText(this, e.message ?: e.toString(), Toast.LENGTH_LONG).show()
                        finish()
                    }
                }
            }
        }
    }

    /** Lists the folder on top of the stack, or the roots. */
    private fun load() {
        val f = files ?: return
        val path = stack.lastOrNull()?.path
        val mine = ++generation
        loading = true
        error = null
        thread(name = "files-list") {
            val result = runCatching { if (path == null) f.roots() else f.list(path) }
            runOnUiThread {
                if (mine != generation || finished) return@runOnUiThread
                loading = false
                entries.clear()
                result.onSuccess { entries.addAll(it) }.onFailure { error = it.message ?: it.toString() }
            }
        }
    }

    private fun open(entry: FileEntry) {
        stack.add(entry)
        load()
    }

    private fun up() {
        if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
        load()
    }

    /** Copies a file or a whole folder into the phone's Downloads. */
    private fun download(entry: FileEntry) {
        val f = files ?: return
        if (transfer != null) return
        transfer = entry.name to null
        thread(name = "files-download") {
            val staging = Transfers.stagingDir(this, "downloads")
            val result = runCatching {
                val names = f.download(entry.path, staging.absolutePath, ProgressListener { p ->
                    runOnUiThread { if (transfer != null) transfer = entry.name to p }
                })
                names.map { Transfers.publish(applicationContext, File(staging, it)) }
            }
            staging.deleteRecursively()
            runOnUiThread {
                transfer = null
                result.onSuccess { toast(getString(R.string.saved_to_downloads, it.joinToString(", "))) }
                    .onFailure { if (!finished) toast(getString(R.string.transfer_failed, it.message ?: it.toString())) }
            }
        }
    }

    /** Sends picked documents into the folder shown (at the roots: the computer's Downloads). */
    private fun upload(uris: List<Uri>) {
        val f = files ?: return
        if (transfer != null) return
        val dir = stack.lastOrNull()?.path ?: ""
        val label = resources.getQuantityString(R.plurals.items_count, uris.size, uris.size)
        transfer = label to null
        thread(name = "files-upload") {
            val staging = Transfers.stagingDir(this, "outgoing")
            val result = runCatching {
                val paths = Transfers.copyIn(this, uris, staging)
                runOnUiThread { if (transfer != null) transfer = label to 0f }
                f.upload(paths, dir, ProgressListener { p -> runOnUiThread { if (transfer != null) transfer = label to p } })
            }
            staging.deleteRecursively()
            runOnUiThread {
                transfer = null
                result.onSuccess {
                    toast(getString(R.string.sent_to, host, it.joinToString(", ")))
                    if (stack.lastOrNull()?.path == dir.ifEmpty { null }) load()
                }.onFailure { if (!finished) toast(getString(R.string.transfer_failed, it.message ?: it.toString())) }
            }
        }
    }

    @Composable
    private fun Screen() {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 20.dp, vertical = 16.dp)) {
            val folder = stack.lastOrNull()
            PageHeader(stringResource(R.string.files), folder?.name ?: host, folder?.path)
            Spacer(Modifier.height(16.dp))
            if (stack.isNotEmpty()) {
                SecondaryButton(stringResource(R.string.files_up), ::up)
                Spacer(Modifier.height(12.dp))
            }
            Box(Modifier.weight(1f)) {
                when {
                    loading -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = Velora.AccentText, strokeWidth = 2.dp)
                        Text(stringResource(R.string.files_loading), style = MaterialTheme.typography.bodyLarge, color = Velora.Weak)
                    }
                    error != null -> Text(error ?: "", style = MaterialTheme.typography.bodyMedium, color = Velora.Error)
                    entries.isEmpty() -> Text(stringResource(R.string.files_empty), style = MaterialTheme.typography.bodyMedium, color = Velora.Weak)
                    else -> EntryList(entries)
                }
            }
            Spacer(Modifier.height(16.dp))
            transfer?.let { (name, progress) ->
                TransferStatus(name, progress)
                Spacer(Modifier.height(12.dp))
            }
            PrimaryButton(
                stringResource(if (stack.isEmpty()) R.string.upload_to_downloads else R.string.upload_here),
                { pick.launch(arrayOf("*/*")) },
                Modifier.fillMaxWidth(),
                enabled = files != null && transfer == null,
                icon = R.drawable.ic_upload,
            )
        }
    }

    @Composable
    private fun EntryList(list: List<FileEntry>) {
        VeloraCard(padding = PaddingValues(0.dp)) {
            LazyColumn {
                itemsIndexed(list) { i, entry ->
                    if (i > 0) HorizontalDivider(color = Velora.Border, thickness = 1.dp)
                    val isFile = entry.kind == FileKind.FILE
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { if (isFile) download(entry) else open(entry) }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        IconTile(if (isFile) R.drawable.ic_file else R.drawable.ic_folder, size = 36)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                entry.name,
                                style = MaterialTheme.typography.titleSmall.copy(fontSize = 15.sp),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            if (isFile) {
                                Text(
                                    Transfers.size(entry.size.toLong()),
                                    style = TextStyle(fontFamily = Velora.Mono, fontSize = 12.sp, color = Velora.Weak),
                                )
                            }
                        }
                        // Folders download whole; a drive is too big for that.
                        if (entry.kind != FileKind.PLACE) {
                            Spacer(Modifier.width(8.dp))
                            Icon(
                                painterResource(R.drawable.ic_download),
                                contentDescription = stringResource(R.string.download),
                                tint = if (transfer == null) Velora.AccentText else Velora.Faint,
                                modifier = Modifier.size(40.dp).clickable(enabled = transfer == null) { download(entry) }.padding(10.dp),
                            )
                        }
                    }
                }
            }
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun finish() {
        finished = true
        super.finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        finished = true
        // Stops a transfer under way too.
        files?.let {
            it.disconnect()
            it.close()
        }
        files = null
    }

    companion object {
        private const val TAG = "FilesActivity"
        private const val EXTRA_HOST = "host"

        fun open(context: Context, host: String) =
            context.startActivity(Intent(context, FilesActivity::class.java).putExtra(EXTRA_HOST, host))
    }
}

/** A transfer's name and progress (null: preparing or connecting; 0: waiting for the computer to accept). */
@Composable
fun TransferStatus(name: String, progress: Float?) {
    VeloraCard(padding = PaddingValues(16.dp)) {
        val started = progress != null && progress > 0f
        Text(
            when {
                started -> stringResource(R.string.transfer_progress, name, ((progress ?: 0f) * 100).toInt())
                progress == null -> stringResource(R.string.transfer_preparing, name)
                else -> stringResource(R.string.transfer_waiting, name)
            },
            style = MaterialTheme.typography.bodyMedium,
            color = Velora.Weak,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(10.dp))
        if (started) {
            LinearProgressIndicator(progress = { progress ?: 0f }, modifier = Modifier.fillMaxWidth(), color = Velora.Accent, trackColor = Velora.Border)
        } else {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Velora.Accent, trackColor = Velora.Border)
        }
    }
}

/** The computer has an access password: ask for it. Never stored. */
@Composable
fun PasswordPrompt(name: String, wrong: Boolean, onSubmit: (String) -> Unit, onCancel: () -> Unit) {
    var password by remember { mutableStateOf("") }
    VeloraDialog(onDismiss = onCancel) {
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
            SecondaryButton(stringResource(R.string.cancel), onCancel, Modifier.weight(1f))
            PrimaryButton(stringResource(R.string.connect), { onSubmit(password) }, Modifier.weight(1f), enabled = password.isNotEmpty())
        }
    }
}
