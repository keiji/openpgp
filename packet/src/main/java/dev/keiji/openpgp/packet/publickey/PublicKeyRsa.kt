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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyRsa

        if (n != null) {
            if (other.n == null) return false
            if (!n.contentEquals(other.n)) return false
        } else if (other.n != null) return false
        if (e != null) {
            if (other.e == null) return false
            if (!e.contentEquals(other.e)) return false
        } else if (other.e != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = n?.contentHashCode() ?: 0
        result = 31 * result + (e?.contentHashCode() ?: 0)
        return result
    }


}
