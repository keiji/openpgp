package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.PublicKeyAlgorithm
import java.io.InputStream

object SignatureParser {
    fun parse(publicKeyAlgorithm: PublicKeyAlgorithm, inputStream: InputStream): Signature? {
        return when (publicKeyAlgorithm) {
            PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN -> SignatureRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.RSA_SIGN_ONLY -> SignatureRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.ECDSA -> SignatureEcdsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.EDDSA_LEGACY -> SignatureEddsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.ED25519 -> SignatureEd25519().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.ED448 -> SignatureEd448().also {
                it.readFrom(inputStream)
            }

            else -> null
        }
    }
}
