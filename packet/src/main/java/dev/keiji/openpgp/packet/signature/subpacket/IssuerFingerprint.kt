package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class IssuerFingerprint : Subpacket() {
    override val typeValue: Int = SubpacketType.IssuerFingerprint.value

    var version: Int = 0
    var fingerprint: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        version = inputStream.read()
        fingerprint = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(version)
        outputStream.write(fingerprint)
    }

    override fun toDebugString(): String {
        return " * IssuerFingerprint\n" +
                "   * version: $version\n" +
                "   * fingerprint: ${fingerprint.toHex("")}\n" +
                ""
    }
}
