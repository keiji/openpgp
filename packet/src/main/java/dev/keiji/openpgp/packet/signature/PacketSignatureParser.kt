package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketSignatureParser {
    fun parse(inputStream: InputStream): PacketSignature {
        val version = inputStream.read()
        return when (version) {
            PacketSignatureV4.VERSION -> PacketSignatureV4().also { it.readFrom(inputStream) }
            PacketSignatureV5.VERSION -> PacketSignatureV5().also { it.readFrom(inputStream) }
            else -> throw UnsupportedVersionException("Signature version $version is unsupported.")
        }
    }
}
