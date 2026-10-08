package dev.keiji.openpgp.packet.pkesk

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketPublicKeyEncryptedSessionKeyParser {
    fun parse(inputStream: InputStream): PacketPublicKeyEncryptedSessionKey {
        val version = inputStream.read()
        return when (version) {
            PacketPublicKeyEncryptedSessionKeyV3.VERSION -> {
                PacketPublicKeyEncryptedSessionKeyV3().also { it.readContentFrom(inputStream) }
            }

            PacketPublicKeyEncryptedSessionKeyV6.VERSION -> {
                PacketPublicKeyEncryptedSessionKeyV6().also { it.readContentFrom(inputStream) }
            }

            else -> {
                throw UnsupportedVersionException(
                    "PublicKeyEncryptedSessionKey version $version is unsupported."
                )
            }
        }
    }
}
