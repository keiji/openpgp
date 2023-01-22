package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toInt
import java.io.InputStream
import java.io.OutputStream

class SignatureCreationTime : Subpacket() {
    override val typeValue: Int = SubpacketType.SignatureCreationTime.value

    var value: Int = -1

    override fun readFrom(inputStream: InputStream) {
        value = ByteArray(4).let {
            inputStream.read(it)
            it.toInt()
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val bytes = value.toByteArray()
        outputStream.write(bytes)
    }

    override fun toDebugString(): String {
        return " * SignatureCreationTime\n" +
                "   * value: $value\n" +
                ""
    }
}
