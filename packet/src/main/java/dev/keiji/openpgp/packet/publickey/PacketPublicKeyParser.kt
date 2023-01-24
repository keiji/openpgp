package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketPublicKeyParser {
    fun parse(inputStream: InputStream): PacketPublicKey {
        val version = inputStream.read()
        return when (version) {
            PacketPublicKeyV4.VERSION -> PacketPublicKeyV4().also { it.readContentFrom(inputStream) }
            PacketPublicKeyV5.VERSION -> PacketPublicKeyV5().also { it.readContentFrom(inputStream) }
            else -> throw UnsupportedVersionException("PublicKey version $version is unsupported.")
        }
    }
}
