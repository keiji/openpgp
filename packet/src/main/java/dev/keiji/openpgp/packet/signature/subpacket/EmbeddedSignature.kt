package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.packet.signature.PacketSignature
import dev.keiji.openpgp.packet.signature.PacketSignatureParser
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class EmbeddedSignature : Subpacket() {
    override val typeValue: Int = SubpacketType.EmbeddedSignature.value

    var signature: PacketSignature? = null

    override fun readFrom(inputStream: InputStream) {
        signature = PacketSignatureParser.parse(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        signature?.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        return " * EmbeddedSignature\n" +
                "   * signature: ${signature?.toDebugString()}\n" +
                ""
    }
}
