package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class SignatureRsa : Signature() {
    // m**d mod n
    var value: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        value = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val valueSnapshot = value ?: return
        MpIntegerUtils.writeTo(valueSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return " * SignatureRsa\n" +
                "   * value: ${value?.toHex("")}\n" +
                ""
    }
}
