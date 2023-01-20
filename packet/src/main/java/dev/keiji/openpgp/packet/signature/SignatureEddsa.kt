package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class SignatureEddsa : Signature() {
    // EC point r.
    var r: ByteArray? = null

    // EdDSA value s, in the little endian representation.
    var s: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        r = MpIntegerUtils.readFrom(inputStream)
        s = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val rSnapshot = r ?: return
        val sSnapshot = s ?: return
        MpIntegerUtils.writeTo(rSnapshot, outputStream)
        MpIntegerUtils.writeTo(sSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return " * SignatureEddsa\n" +
                "   * r: ${r?.toHex("")}\n" +
                "   * s: ${s?.toHex("")}\n" +
                ""
    }
}
