package dev.keiji.openpgp.packet.userattribute.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class Unknown(override val typeValue: Int) : Subpacket() {
    var values: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        values = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return " * Unknown\n" +
                "   * values: ${values.toHex("")}\n" +
                ""
    }
}
