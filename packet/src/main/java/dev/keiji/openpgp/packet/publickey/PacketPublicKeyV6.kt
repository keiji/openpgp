@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toInt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * A version 6 Public Key packet.
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.2.3
 */
open class PacketPublicKeyV6 : PacketPublicKey() {
    companion object {
        const val VERSION: Int = 6
    }

    override val version: Int = VERSION

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val publicKeyAlgorithmByte = inputStream.read()
        algorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException(
                "PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported"
            )

        val keyBodyLengthBytes = ByteArray(4)
        inputStream.read(keyBodyLengthBytes)
        val keyBodyLength = keyBodyLengthBytes.toInt()

        val keyBodyBytesInputStream = ByteArray(keyBodyLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        publicKey = readPublicKeyFrom(keyBodyBytesInputStream)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val publicKeySnapshot = publicKey
            ?: throw UnsupportedAlgorithmException("publicKey must not be null.")

        super.writeContentTo(outputStream)

        outputStream.write(algorithm.id)

        val keyBodyLengthBytes = ByteArrayOutputStream().let {
            publicKeySnapshot.writeTo(it)
            it.toByteArray()
        }
        val keyBodyLength = keyBodyLengthBytes.size
        outputStream.write(keyBodyLength.toByteArray())
        outputStream.write(keyBodyLengthBytes)
    }

    @Suppress("CyclomaticComplexMethod", "LongMethod")
    private fun readPublicKeyFrom(inputStream: ByteArrayInputStream): PublicKey {
        return when (algorithm) {
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

            PublicKeyAlgorithm.ED25519 -> PublicKeyEd25519().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.ED448 -> PublicKeyEd448().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.X25519 -> PublicKeyX25519().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.X448 -> PublicKeyX448().also {
                it.readFrom(inputStream)
            }

            else -> throw UnsupportedAlgorithmException("algorithm ${algorithm.name} is not supported.")
        }
    }

    override fun toDebugString(): String {
        return " * PacketPublicKeyV6\n" +
                "   * Version: $version\n" +
                "   * Algorithm: ${algorithm.name}\n" +
                "   * PublicKey: ${publicKey?.toDebugString()}" +
                ""
    }
}
