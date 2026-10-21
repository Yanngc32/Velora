package io.github.yanngc32.velora

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import uniffi.velora_mobile.HostEntry

class MainActivity : ComponentActivity() {
    private val hosts = mutableStateListOf<HostEntry>()
    /** Pairing form contents; non-null while the form is shown. */
    private var pairing by mutableStateOf<PairingLink?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = VeloraColors) {
                Surface(Modifier.fillMaxSize()) {
                    HostsScreen(
                        hosts = hosts,
                        onConnect = { SessionActivity.connect(this, it.name) },
                        onForget = { forget(it) },
                        onScan = ::scan,
                        onManual = { pairing = PairingLink("", "") },
                    )
                    pairing?.let { link ->
                        PairDialog(
                            initial = link,
                            onPair = { address, code ->
                                pairing = null
                                SessionActivity.pair(this, address.trim(), code.trim())
                            },
                            onDismiss = { pairing = null },
                        )
                    }
                }
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

/** The Velora palette: dark ink background, teal actions, lavender and lime accents. */
private val Ink = Color(0xFF0B0B0F)
private val Card = Color(0xFF16141F)
private val VeloraColors = darkColorScheme(
    primary = Color(0xFF4EE1C3),
    onPrimary = Ink,
    secondary = Color(0xFFB388FF),
    onSecondary = Ink,
    tertiary = Color(0xFFB8FF6A),
    onTertiary = Ink,
    background = Ink,
    onBackground = Color(0xFFF2F1F7),
    surface = Ink,
    onSurface = Color(0xFFF2F1F7),
    surfaceVariant = Card,
    onSurfaceVariant = Color(0xFFB9B6C9),
    surfaceContainerHigh = Card,
    outline = Color(0xFF3B2A6F),
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HostsScreen(
    hosts: List<HostEntry>,
    onConnect: (HostEntry) -> Unit,
    onForget: (HostEntry) -> Unit,
    onScan: () -> Unit,
    onManual: () -> Unit,
) {
    var confirmForget by remember { mutableStateOf<HostEntry?>(null) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Column {
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
            Text(
                stringResource(R.string.tagline).uppercase(),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        if (hosts.isEmpty()) {
            Text(stringResource(R.string.no_hosts), style = MaterialTheme.typography.bodyLarge)
        }
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(hosts, key = { it.name }) { host ->
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth().combinedClickable(
                        onClick = { onConnect(host) },
                        onLongClick = { confirmForget = host },
                    ),
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text(host.name, style = MaterialTheme.typography.titleMedium)
                        Text(host.address, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onScan) { Text(stringResource(R.string.scan_qr)) }
            OutlinedButton(onClick = onManual) { Text(stringResource(R.string.enter_code)) }
        }
    }
    confirmForget?.let { host ->
        AlertDialog(
            onDismissRequest = { confirmForget = null },
            title = { Text(stringResource(R.string.forget_title, host.name)) },
            confirmButton = {
                TextButton(onClick = { onForget(host); confirmForget = null }) { Text(stringResource(R.string.forget)) }
            },
            dismissButton = { TextButton(onClick = { confirmForget = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun PairDialog(initial: PairingLink, onPair: (String, String) -> Unit, onDismiss: () -> Unit) {
    var address by remember { mutableStateOf(initial.address) }
    var code by remember { mutableStateOf(initial.code) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.pair_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.pair_hint))
                OutlinedTextField(address, { address = it }, label = { Text(stringResource(R.string.address)) }, singleLine = true)
                OutlinedTextField(code, { code = it }, label = { Text(stringResource(R.string.code)) }, singleLine = true)
            }
        },
        confirmButton = {
            TextButton(enabled = address.isNotBlank() && code.startsWith("VL1-"), onClick = { onPair(address, code) }) {
                Text(stringResource(R.string.pair))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
