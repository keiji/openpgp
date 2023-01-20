package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketPublicSubkeyParser {
    fun parse(inputStream: InputStream): PacketPublicKey {
        val version = inputStream.read()
        return when (version) {
            PacketPublicKeyV4.VERSION -> PacketPublicSubkeyV4().also { it.readFrom(inputStream) }
            PacketPublicKeyV5.VERSION -> PacketPublicSubkeyV5().also { it.readFrom(inputStream) }
            else -> throw UnsupportedVersionException("PublicSubkey version $version is unsupported.")
        }
    }
}
