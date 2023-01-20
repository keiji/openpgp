package dev.keiji.openpgp.packet.signature.subpacket

import java.io.InputStream
import java.io.OutputStream

class TrustSignature : Subpacket() {
    override val typeValue: Int = SubpacketType.TrustSignature.value

    var level: Int = -1

    override fun readFrom(inputStream: InputStream) {
        level = inputStream.read()
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(level)
    }

    override fun toDebugString(): String {
        return " * TrustSignature\n" +
                "   * level: $level\n" +
                ""
    }
}
