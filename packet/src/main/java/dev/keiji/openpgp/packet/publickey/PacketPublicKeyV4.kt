package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

open class PacketPublicKeyV4 : PacketPublicKey() {
    companion object {
        const val VERSION: Int = 4
    }

    override val version: Int = VERSION

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val publicKeyAlgorithmByte = inputStream.read()
        algorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException(
                "PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported"
            )

        publicKey = when (algorithm) {
            PublicKeyAlgorithm.ECDSA -> PublicKeyEcdsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.ECDH -> PublicKeyEcdh().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN -> PublicKeyRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.RSA_SIGN_ONLY -> PublicKeyRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.RSA_ENCRYPT_ONLY -> PublicKeyRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.EDDSA_LEGACY -> PublicKeyEddsa().also {
                it.readFrom(inputStream)
            }

            else -> throw UnsupportedAlgorithmException("algorithm ${algorithm.name} is not supported.")
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val publicKeySnapshot =
            publicKey ?: throw InvalidParameterException("publicKey must not be null.")

        super.writeContentTo(outputStream)

        outputStream.write(algorithm.id)
        publicKeySnapshot.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        return """
 * PacketPublicKeyV4
    * Version: $version
    * Algorithm: ${algorithm.name}
    * PublicKey:
    ${publicKey?.toString()}            
        """.trimIndent()
    }
}
