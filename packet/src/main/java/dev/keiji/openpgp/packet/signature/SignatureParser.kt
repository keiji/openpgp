package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.OpenPgpAlgorithm
import java.io.InputStream

object SignatureParser {
    fun parse(publicKeyAlgorithm: OpenPgpAlgorithm, inputStream: InputStream): Signature? {
        return when (publicKeyAlgorithm) {
            OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN -> SignatureRsa().also {
                it.readFrom(inputStream)
            }
            OpenPgpAlgorithm.ECDSA -> SignatureEcdsa().also {
                it.readFrom(inputStream)
            }
            OpenPgpAlgorithm.EDDSA -> SignatureEddsa().also {
                it.readFrom(inputStream)
            }
            else -> null
        }
    }
}
