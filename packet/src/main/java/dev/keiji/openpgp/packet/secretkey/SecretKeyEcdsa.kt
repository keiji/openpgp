package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class SecretKeyEcdsa : SecretKey() {

    var value: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {

        // Note that this form is in reverse octet order from the little-endian "native" form found in RFC7748.
        value = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val valueSnapshot =
            value ?: throw InvalidParameterException("parameter `value` must not be null")

        MpIntegerUtils.writeTo(valueSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return " * SecretKeyEcdh\n" +
                "   * value: ${value?.toHex("")}\n" +
                ""
    }
}
