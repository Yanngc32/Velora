package io.github.yanngc32.velora

import android.app.Application
import android.content.Context
import android.os.Build
import uniffi.velora_mobile.Client

class App : Application() {
    /** Identity and paired hosts live in the app's private storage. */
    val client: Client by lazy { Client(filesDir.absolutePath, Build.MODEL ?: "Android") }
}

val Context.client: Client get() = (applicationContext as App).client
