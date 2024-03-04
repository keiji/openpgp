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

open class PacketPublicKeyV5 : PacketPublicKey() {
    companion object {
        const val VERSION: Int = 5
    }

    override val version: Int = VERSION

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val publicKeyAlgorithmByte = inputStream.read()
        algorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException("PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported")

        val keyBodyLengthBytes = ByteArray(4)
        inputStream.read(keyBodyLengthBytes)
        val keyBodyLength = keyBodyLengthBytes.toInt()

        val keyBodyBytesInputStream = ByteArray(keyBodyLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        publicKey = when (algorithm) {
            PublicKeyAlgorithm.ECDSA -> PublicKeyEcdsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            PublicKeyAlgorithm.ECDH -> PublicKeyEcdh().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN -> PublicKeyRsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            PublicKeyAlgorithm.RSA_SIGN_ONLY -> PublicKeyRsa().also {
                it.readFrom(inputStream)
            }

            PublicKeyAlgorithm.RSA_ENCRYPT_ONLY -> PublicKeyRsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            PublicKeyAlgorithm.EDDSA_LEGACY -> PublicKeyEddsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            else -> throw UnsupportedAlgorithmException("algorithm ${algorithm.name} is not supported.")
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        super.writeContentTo(outputStream)

        outputStream.write(algorithm.id)

        val keyBodyLengthBytes = ByteArrayOutputStream().let {
            publicKey?.writeTo(it)
            it.toByteArray()
        }
        val keyBodyLength = keyBodyLengthBytes.size
        outputStream.write(keyBodyLength.toByteArray())
        outputStream.write(keyBodyLengthBytes)
    }

    override fun toDebugString(): String {
        return " * PacketPublicKeyV5\n" +
                "   * Version: $version\n" +
                "   * Algorithm: ${algorithm.name}\n" +
                "   * PublicKey: ${publicKey?.toDebugString()}" +
                ""
    }
}
