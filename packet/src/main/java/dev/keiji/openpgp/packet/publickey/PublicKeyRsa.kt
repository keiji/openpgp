package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PublicKeyRsa : PublicKey() {
    var n: ByteArray? = null
    var e: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        n = MpIntegerUtils.readFrom(inputStream)
        e = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val nSnapshot = n ?: throw InvalidParameterException("parameter `n` must not be null")
        val eSnapshot = e ?: throw InvalidParameterException("parameter `e` must not be null")
        MpIntegerUtils.writeTo(nSnapshot, outputStream)
        MpIntegerUtils.writeTo(eSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return """
* PublicKey RSA
    * n: ${n?.toHex()}
    * e: ${e?.toHex()}
        """.trimIndent()
    }
}
