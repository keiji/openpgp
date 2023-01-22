package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class AttestedCertifications : Subpacket() {
    override val typeValue: Int = SubpacketType.AttestedCertifications.value

    var digests: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        digests = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(digests)
    }

    override fun toDebugString(): String {
        return " * AttestedCertifications\n" +
                "   * digests: ${digests.toHex("")}\n" +
                ""
    }
}
