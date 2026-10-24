package io.github.yanngc32.velora

import android.Manifest
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlin.concurrent.thread
import uniffi.velora_mobile.ConnectionMode
import uniffi.velora_mobile.HostEntry

class MainActivity : ComponentActivity() {
    private val hosts = mutableStateListOf<HostEntry>()
    /** Pairing form contents; non-null while the form is shown. */
    private var pairing by mutableStateOf<PairingLink?>(null)
    private var update by mutableStateOf<Updater.Update?>(null)
    /** Download progress (0..1) while an update is being fetched. */
    private var updateProgress by mutableStateOf<Float?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            VeloraTheme {
                Box(Modifier.fillMaxSize().background(Velora.Bg)) {
                    HostsScreen(
                        hosts = hosts,
                        onConnect = { SessionActivity.connect(this@MainActivity, it.name) },
                        onFiles = { FilesActivity.open(this@MainActivity, it.name) },
                        onForget = { forget(it) },
                        modeOf = { host -> runCatching { client.connectionMode(host.name) }.getOrDefault(ConnectionMode.AUTO) },
                        onMode = { host, mode -> runCatching { client.setConnectionMode(host.name, mode) }.onFailure { toast(it.message) } },
                        onScan = ::scan,
                        onManual = { pairing = PairingLink("", "") },
                        update = update,
                        updateProgress = updateProgress,
                        onUpdate = ::installUpdate,
                    )
                    pairing?.let { link ->
                        PairDialog(
                            initial = link,
                            onPair = { address, code ->
                                pairing = null
                                SessionActivity.pair(this@MainActivity, address.trim(), code.trim())
                            },
                            onDismiss = { pairing = null },
                        )
                    }
                }
            }
        }
        if (savedInstanceState == null) checkForUpdate()
        // Android 8-9: received and downloaded files go to the public Downloads folder only
        // with this permission (without it, to the app's own folder on the shared storage).
        if (savedInstanceState == null && Transfers.needsLegacyPermission(this)) {
            requestPermissions(arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        }
    }

    private fun checkForUpdate() {
        thread {
            // Offline or rate-limited: try again next launch.
            val found = runCatching { Updater.check() }.getOrNull()
            runOnUiThread { update = found }
        }
    }

    private fun installUpdate() {
        val target = update ?: return
        updateProgress = 0f
        thread {
            val result = runCatching { Updater.install(applicationContext, target) { p -> runOnUiThread { updateProgress = p } } }
            runOnUiThread {
                updateProgress = null
                result.onFailure { toast(getString(R.string.update_failed, it.message ?: "")) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // A session may have just paired a new host.
        hosts.clear()
        runCatching { client.hosts() }.onSuccess { hosts.addAll(it) }.onFailure { toast(it.message) }
    }

    /** Google's code scanner: no camera permission needed, the scan UI runs in Play services. */
    private fun scan() {
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { barcode ->
                val link = PairingLink.parse(barcode.rawValue ?: "")
                if (link != null) pairing = link else toast(getString(R.string.not_a_pairing_code))
            }
            .addOnFailureListener { toast(getString(R.string.scanner_unavailable)) }
    }

    private fun forget(host: HostEntry) {
        runCatching { client.forget(host.name) }.onFailure { toast(it.message) }
        hosts.remove(host)
    }

    private fun toast(message: String?) {
        Toast.makeText(this, message ?: "?", Toast.LENGTH_LONG).show()
    }
}

@Composable
private fun HostsScreen(
    hosts: List<HostEntry>,
    onConnect: (HostEntry) -> Unit,
    onFiles: (HostEntry) -> Unit,
    onForget: (HostEntry) -> Unit,
    modeOf: (HostEntry) -> ConnectionMode,
    onMode: (HostEntry, ConnectionMode) -> Unit,
    onScan: () -> Unit,
    onManual: () -> Unit,
    update: Updater.Update?,
    updateProgress: Float?,
    onUpdate: () -> Unit,
) {
    var confirmForget by remember { mutableStateOf<HostEntry?>(null) }
    /** The computer whose options (connection mode, forget) are shown, after a long press. */
    var options by remember { mutableStateOf<HostEntry?>(null) }
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 20.dp, vertical = 16.dp)) {
        Brand()
        Spacer(Modifier.height(28.dp))
        update?.let {
            UpdateBanner(it, updateProgress, onUpdate)
            Spacer(Modifier.height(20.dp))
        }
        val count = if (hosts.isEmpty()) null else pluralStringResource(R.plurals.devices_count, hosts.size, hosts.size)
        PageHeader(stringResource(R.string.devices_label), stringResource(R.string.devices_title), count)
        Spacer(Modifier.height(20.dp))
        Box(Modifier.weight(1f)) {
            if (hosts.isEmpty()) EmptyDevices(onScan) else DeviceList(hosts, onConnect, onFiles, onLongPress = { options = it })
        }
        Spacer(Modifier.height(16.dp))
        PrimaryButton(stringResource(R.string.scan_qr), onScan, Modifier.fillMaxWidth(), icon = R.drawable.ic_scan_qr_code)
        Spacer(Modifier.height(10.dp))
        SecondaryButton(stringResource(R.string.enter_code), onManual, Modifier.fillMaxWidth(), icon = R.drawable.ic_keyboard)
    }
    options?.let { host ->
        HostOptions(
            host = host,
            initial = modeOf(host),
            onMode = { onMode(host, it) },
            onForget = { options = null; confirmForget = host },
            onDismiss = { options = null },
        )
    }
    confirmForget?.let { host ->
        VeloraDialog(onDismiss = { confirmForget = null }) {
            Text(stringResource(R.string.forget_title, host.name), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(stringResource(R.string.forget_text), style = MaterialTheme.typography.bodyMedium, color = Velora.Weak)
            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SecondaryButton(stringResource(R.string.cancel), { confirmForget = null }, Modifier.weight(1f))
                PrimaryButton(stringResource(R.string.forget), { onForget(host); confirmForget = null }, Modifier.weight(1f))
            }
        }
    }
}

/** What a long press on a computer offers: how to reach it, and forgetting it. */
@Composable
private fun HostOptions(
    host: HostEntry,
    initial: ConnectionMode,
    onMode: (ConnectionMode) -> Unit,
    onForget: () -> Unit,
    onDismiss: () -> Unit,
) {
    var mode by remember { mutableStateOf(initial) }
    VeloraDialog(onDismiss) {
        Text(host.name, style = MaterialTheme.typography.titleMedium.copy(fontSize = 17.sp))
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.connection_mode), style = MaterialTheme.typography.bodyMedium, color = Velora.Weak)
        Spacer(Modifier.height(12.dp))
        for ((choice, name, hint) in listOf(
            Triple(ConnectionMode.AUTO, R.string.mode_auto, R.string.mode_auto_hint),
            Triple(ConnectionMode.LAN, R.string.mode_lan, R.string.mode_lan_hint),
            Triple(ConnectionMode.VPN, R.string.mode_vpn, R.string.mode_vpn_hint),
            Triple(ConnectionMode.VELORA, R.string.mode_velora, R.string.mode_velora_hint),
        )) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { mode = choice; onMode(choice) }
                    .padding(vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = mode == choice,
                    onClick = { mode = choice; onMode(choice) },
                    colors = RadioButtonDefaults.colors(selectedColor = Velora.AccentText),
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(name), style = MaterialTheme.typography.titleSmall.copy(fontSize = 15.sp))
                    Text(stringResource(hint), style = MaterialTheme.typography.bodySmall, color = Velora.Weak)
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton(stringResource(R.string.forget), onForget, Modifier.weight(1f))
            PrimaryButton(stringResource(R.string.done), onDismiss, Modifier.weight(1f))
        }
    }
}

/** Logo and name, as at the top of the desktop sidebar. */
@Composable
private fun Brand() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Image(
            painterResource(R.drawable.velora_logo),
            contentDescription = null,
            modifier = Modifier.size(28.dp).clip(RoundedCornerShape(6.dp)),
        )
        Spacer(Modifier.width(10.dp))
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleMedium.copy(fontSize = 17.sp))
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DeviceList(
    hosts: List<HostEntry>,
    onConnect: (HostEntry) -> Unit,
    onFiles: (HostEntry) -> Unit,
    onLongPress: (HostEntry) -> Unit,
) {
    VeloraCard(padding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
        LazyColumn {
            itemsIndexed(hosts, key = { _, h -> h.name }) { i, host ->
                if (i > 0) HorizontalDivider(color = Velora.Border, thickness = 1.dp)
                Row(
                    Modifier
                        .fillMaxWidth()
                        .combinedClickable(onClick = { onConnect(host) }, onLongClick = { onLongPress(host) })
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconTile(R.drawable.ic_monitor)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(host.name, style = MaterialTheme.typography.titleSmall.copy(fontSize = 15.sp))
                        Text(host.address, style = TextStyle(fontFamily = Velora.Mono, fontSize = 12.sp, color = Velora.Weak))
                    }
                    Spacer(Modifier.width(8.dp))
                    SecondaryButton(stringResource(R.string.files), { onFiles(host) })
                    Spacer(Modifier.width(8.dp))
                    PrimaryButton(stringResource(R.string.connect), { onConnect(host) })
                }
            }
        }
    }
}

@Composable
private fun UpdateBanner(update: Updater.Update, progress: Float?, onUpdate: () -> Unit) {
    VeloraCard(padding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(stringResource(R.string.update_title, update.version), style = MaterialTheme.typography.titleSmall.copy(fontSize = 15.sp))
                Text(
                    if (progress == null) stringResource(R.string.update_text)
                    else stringResource(R.string.update_downloading, (progress * 100).toInt()),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Velora.Weak,
                )
            }
            Spacer(Modifier.width(8.dp))
            PrimaryButton(stringResource(R.string.update), onUpdate, enabled = progress == null)
        }
    }
}

/** Like the desktop's empty device list. */
@Composable
private fun EmptyDevices(onScan: () -> Unit) {
    VeloraCard(padding = androidx.compose.foundation.layout.PaddingValues(24.dp)) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(painterResource(R.drawable.ic_monitor), contentDescription = null, tint = Velora.Faint, modifier = Modifier.size(32.dp))
            Spacer(Modifier.height(14.dp))
            Text(stringResource(R.string.no_hosts_title), style = MaterialTheme.typography.titleMedium.copy(fontSize = 16.sp))
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.no_hosts),
                style = MaterialTheme.typography.bodyMedium,
                color = Velora.Weak,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** A card-styled dialog, like the desktop's password prompt. */
@Composable
fun VeloraDialog(onDismiss: () -> Unit, content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        VeloraCard(padding = androidx.compose.foundation.layout.PaddingValues(24.dp), content = content)
    }
}

@Composable
private fun PairDialog(initial: PairingLink, onPair: (String, String) -> Unit, onDismiss: () -> Unit) {
    var address by remember { mutableStateOf(initial.address) }
    var code by remember { mutableStateOf(initial.code) }
    VeloraDialog(onDismiss) {
        Text(stringResource(R.string.pair_title), style = MaterialTheme.typography.titleMedium.copy(fontSize = 17.sp))
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.pair_hint), style = MaterialTheme.typography.bodyMedium, color = Velora.Weak)
        Spacer(Modifier.height(18.dp))
        Field(stringResource(R.string.code), code, { code = it }, placeholder = "VL1-…", technical = true)
        Spacer(Modifier.height(12.dp))
        Field(stringResource(R.string.address), address, { address = it }, placeholder = "192.168.0.10:7420", technical = true)
        Spacer(Modifier.height(20.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton(stringResource(R.string.cancel), onDismiss, Modifier.weight(1f))
            PrimaryButton(
                stringResource(R.string.pair),
                { onPair(address, code) },
                Modifier.weight(1f),
                enabled = address.isNotBlank() && code.trim().startsWith("VL1-"),
            )
        }
    }
}
