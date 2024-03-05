@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toInt
import java.io.InputStream
import java.io.OutputStream

class KeyExpirationTime : Subpacket() {
    override val typeValue: Int = SubpacketType.KeyExpirationTime.value

    var value: Int = -1

    override fun readFrom(inputStream: InputStream) {
        value = ByteArray(4).let {
            inputStream.read(it)
            it.toInt()
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(value.toByteArray())
    }

    override fun toDebugString(): String {
        return " * KeyExpirationTime\n" +
                "   * value: $value\n" +
                ""
    }
}
