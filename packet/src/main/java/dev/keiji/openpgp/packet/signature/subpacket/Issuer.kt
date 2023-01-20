package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class Issuer : Subpacket() {
    override val typeValue: Int = SubpacketType.Issuer.value

    var keyId: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        keyId = inputStream.readBytes()
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(keyId)
    }

    override fun toDebugString(): String {
        return " * Issuer\n" +
                "   * keyId: ${keyId.toHex("")}\n" +
                ""
    }
}
