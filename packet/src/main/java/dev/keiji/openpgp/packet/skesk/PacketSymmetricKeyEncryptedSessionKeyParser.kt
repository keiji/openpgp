package dev.keiji.openpgp.packet.skesk

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketSymmetricKeyEncryptedSessionKeyParser {
    fun parse(inputStream: InputStream): PacketSymmetricKeyEncryptedSessionKey {
        val version = inputStream.read()
        return when (version) {
            PacketSymmetricKeyEncryptedSessionKeyV4.VERSION -> {
                PacketSymmetricKeyEncryptedSessionKeyV4().also { it.readContentFrom(inputStream) }
            }

            PacketSymmetricKeyEncryptedSessionKeyV5.VERSION -> {
                PacketSymmetricKeyEncryptedSessionKeyV5().also { it.readContentFrom(inputStream) }
            }

            else -> {
                throw UnsupportedVersionException("SymmetricKeyEncryptedSessionKey version $version is unsupported.")
            }
        }
    }
}
