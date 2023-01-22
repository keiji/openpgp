package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class KeyServerPreferences : Subpacket() {
    override val typeValue: Int = SubpacketType.KeyServerPreferences.value

    var flags: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        flags = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(flags)
    }

    override fun toDebugString(): String {
        return " * KeyServerPreferences\n" +
                "   * flags: ${flags.toHex("")}\n" +
                ""
    }
}
