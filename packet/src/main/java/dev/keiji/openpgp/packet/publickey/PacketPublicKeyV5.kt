package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.publickey.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

open class PacketPublicKeyV5 : PacketPublicKey() {
    companion object {
        const val VERSION: Int = 5
    }

    override val version: Int = VERSION

    var algorithm: OpenPgpAlgorithm = OpenPgpAlgorithm.ECDSA
    var publicKey: PublicKey? = null

    override fun readFrom(inputStream: InputStream) {
        super.readFrom(inputStream)

        val publicKeyAlgorithmByte = inputStream.read()
        algorithm = OpenPgpAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException("PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported")

        val keyBodyLengthBytes = ByteArray(4)
        inputStream.read(keyBodyLengthBytes)
        val keyBodyLength = keyBodyLengthBytes.toInt()

        val keyBodyBytesInputStream = ByteArray(keyBodyLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        publicKey = when (algorithm) {
            OpenPgpAlgorithm.ECDSA -> PublicKeyEcdsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            OpenPgpAlgorithm.ECDH -> PublicKeyEcdh().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN -> PublicKeyRsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            OpenPgpAlgorithm.RSA_SIGN_ONLY -> PublicKeyRsa().also {
                it.readFrom(inputStream)
            }

            OpenPgpAlgorithm.RSA_ENCRYPT_ONLY -> PublicKeyRsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            OpenPgpAlgorithm.EDDSA -> PublicKeyEddsa().also {
                it.readFrom(keyBodyBytesInputStream)
            }

            else -> throw UnsupportedAlgorithmException("algorithm ${algorithm.name} is not supported.")
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        super.writeTo(outputStream)

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
