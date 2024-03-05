package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class KeyBlock : Subpacket() {
    override val typeValue: Int = SubpacketType.KeyBlock.value

    var keyData: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        // Skip 1 byte
        inputStream.read()

        keyData = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(0)
        outputStream.write(keyData)
    }

    override fun toDebugString(): String {
        return " * KeyBlock\n" +
                "   * keyData: ${keyData.toHex("")}\n" +
                ""
    }
}
