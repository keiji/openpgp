package dev.keiji.openpgp.packet.seipd

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketSymEncryptedAndIntegrityProtectedDataParser {
    fun parse(inputStream: InputStream): PacketSymEncryptedAndIntegrityProtectedData {
        val version = inputStream.read()
        return when (version) {
            PacketSymEncryptedAndIntegrityProtectedDataV1.VERSION -> {
                PacketSymEncryptedAndIntegrityProtectedDataV1().also { it.readContentFrom(inputStream) }
            }
            PacketSymEncryptedAndIntegrityProtectedDataV2.VERSION -> {
                PacketSymEncryptedAndIntegrityProtectedDataV2().also { it.readContentFrom(inputStream) }
            }
            else -> throw UnsupportedVersionException("PacketSymEncryptedAndIntegrityProtectedData version $version is unsupported.")
        }
    }
}
