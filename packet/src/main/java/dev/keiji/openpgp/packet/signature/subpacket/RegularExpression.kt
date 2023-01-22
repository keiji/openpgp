package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class RegularExpression : Subpacket() {
    override val typeValue: Int = SubpacketType.RegularExpression.value

    var values: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        values = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return " * RegularExpression\n" +
                "   * values: ${values.toHex("")}\n" +
                ""
    }
}
