package dev.keiji.openpgp.packet.seipd

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class PacketSymEncryptedAndIntegrityProtectedDataV1 :
    PacketSymEncryptedAndIntegrityProtectedData() {

    companion object {
        const val VERSION = 1
    }

    override val version: Int = VERSION

    var encryptedData: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        encryptedData = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(version)
        outputStream.write(encryptedData)
    }

    override fun toDebugString(): String {
        return " * PacketSymEncryptedAndIntegrityProtectedDataV1\n" +
                "   * Version: $version\n" +
                "   * encryptedData: ${encryptedData.toHex("")}\n" +
                ""
    }
}
