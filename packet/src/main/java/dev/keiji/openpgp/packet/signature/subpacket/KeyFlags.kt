package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class KeyFlags : Subpacket() {
    override val typeValue: Int = SubpacketType.KeyFlags.value

    var flags: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        flags = inputStream.readBytes()
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(flags)
    }

    override fun toDebugString(): String {
        return " * KeyFlags\n" +
                "   * flags: ${flags.toHex("")}\n" +
                ""
    }
}
