package dev.keiji.openpgp

import dev.keiji.util.Base64

object Radix64 {
    fun encode(
        plain: ByteArray,
        charCountOfLine: Int = 64,
        separator: String = "\r\n",
    ): String {
        val encoded = Base64.encode(plain)
        return encoded
            .chunked(charCountOfLine)
            .joinToString(separator)
    }

    fun decode(encoded: String): ByteArray {
        val joined = encoded
            .replace("\r\n", "")
            .replace("\n", "")
        return Base64.decode(joined)
    }
}
