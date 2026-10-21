package io.github.yanngc32.screenmirroring

import java.net.URLDecoder

/** Address and code from the QR code printed by `sm-host run --pair`. */
data class PairingLink(val address: String, val code: String) {
    companion object {
        private const val PREFIX = "screenmirroring://pair?"

        fun parse(text: String): PairingLink? {
            val query = text.trim().takeIf { it.startsWith(PREFIX) }?.removePrefix(PREFIX) ?: return null
            val params = query.split('&').mapNotNull { part ->
                val i = part.indexOf('=')
                if (i <= 0) null else part.substring(0, i) to URLDecoder.decode(part.substring(i + 1), "UTF-8")
            }.toMap()
            val address = params["address"]?.takeIf { it.isNotBlank() } ?: return null
            val code = params["code"]?.takeIf { it.startsWith("SM1-") } ?: return null
            return PairingLink(address, code)
        }
    }
}
