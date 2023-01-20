package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.UnsupportedVersionException
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV5
import java.io.InputStream

object PacketSecretSubkeyParser {
    fun parse(inputStream: InputStream): PacketPublicKey {
        val version = inputStream.read()
        return when (version) {
            PacketPublicKeyV4.VERSION -> PacketSecretSubkeyV4().also { it.readFrom(inputStream) }
            PacketPublicKeyV5.VERSION -> PacketSecretSubkeyV5().also { it.readFrom(inputStream) }
            else -> throw UnsupportedVersionException("SecretSubkey version $version is unsupported.")
        }
    }
}
