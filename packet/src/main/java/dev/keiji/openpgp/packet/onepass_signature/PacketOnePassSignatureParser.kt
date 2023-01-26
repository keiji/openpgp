package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.UnsupportedVersionException
import java.io.InputStream

object PacketOnePassSignatureParser {
    fun parse(inputStream: InputStream): PacketOnePassSignature {
        val version = inputStream.read()
        return when (version) {
            PacketOnePassSignatureV3.VERSION -> {
                PacketOnePassSignatureV3().also { it.readContentFrom(inputStream) }
            }

            PacketOnePassSignatureV5.VERSION -> {
                PacketOnePassSignatureV5().also { it.readContentFrom(inputStream) }
            }

            else -> throw UnsupportedVersionException("PacketOnePassSignature version $version is unsupported.")
        }
    }
}
