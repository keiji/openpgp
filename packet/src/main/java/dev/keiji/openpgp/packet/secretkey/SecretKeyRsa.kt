package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class SecretKeyRsa : SecretKey() {

    var d: ByteArray? = null
    var p: ByteArray? = null
    var q: ByteArray? = null

    // the multiplicative inverse of p, mod q.
    var u: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        d = MpIntegerUtils.readFrom(inputStream)
        p = MpIntegerUtils.readFrom(inputStream)
        q = MpIntegerUtils.readFrom(inputStream)
        u = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val dSnapshot = d ?: throw InvalidParameterException("parameter `d` must not be null")
        val pSnapshot = p ?: throw InvalidParameterException("parameter `p` must not be null")
        val qSnapshot = q ?: throw InvalidParameterException("parameter `q` must not be null")
        val uSnapshot = u ?: throw InvalidParameterException("parameter `u` must not be null")

        MpIntegerUtils.writeTo(dSnapshot, outputStream)
        MpIntegerUtils.writeTo(pSnapshot, outputStream)
        MpIntegerUtils.writeTo(qSnapshot, outputStream)
        MpIntegerUtils.writeTo(uSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return " * SecretKeyEcdh\n" +
                "   * d: ${d?.toHex("")}\n" +
                "   * p: ${p?.toHex("")}\n" +
                "   * q: ${q?.toHex("")}\n" +
                "   * u: ${u?.toHex("")}\n" +
                ""
    }
}
