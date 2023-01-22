package dev.keiji.openpgp.packet.signature.subpacket

import java.io.InputStream
import java.io.OutputStream

private const val REVOCABLE = 1

class Revocable : Subpacket() {
    override val typeValue: Int = SubpacketType.Revocable.value

    var value: Boolean = false

    override fun readFrom(inputStream: InputStream) {
        value = inputStream.read() == REVOCABLE
    }

    override fun writeContentTo(outputStream: OutputStream) {
        if (value) {
            outputStream.write(REVOCABLE)
        } else {
            outputStream.write(0)
        }
    }

    override fun toDebugString(): String {
        return " * Revocable\n" +
                "   * value: $value\n" +
                ""
    }
}
