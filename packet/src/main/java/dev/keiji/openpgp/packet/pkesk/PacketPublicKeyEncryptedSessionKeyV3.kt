package dev.keiji.openpgp.packet.pkesk

import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

/**
 * A version 3 Public Key Encrypted Session Key packet.
 *
 * A v3 PKESK packet precedes a v1 SEIPD packet. It consists of:
 *
 *  -  a 1-octet version number with value 3,
 *  -  an 8-octet Key ID of the public key to which the session key is
 *     encrypted (all zeros for an anonymous recipient),
 *  -  a 1-octet public key algorithm, and
 *  -  the algorithm-specific encrypted session key.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.1
 */
class PacketPublicKeyEncryptedSessionKeyV3 : PacketPublicKeyEncryptedSessionKey() {
    companion object {
        const val VERSION: Int = 3

        const val KEY_ID_LENGTH = 8
    }

    override val version: Int = VERSION

    var keyId: ByteArray = ByteArray(KEY_ID_LENGTH)

    var publicKeyAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN

    var encryptedSessionKey: EncryptedSessionKey? = null

    override fun readContentFrom(inputStream: InputStream) {
        keyId = ByteArray(KEY_ID_LENGTH).also {
            inputStream.read(it)
        }

        val publicKeyAlgorithmByte = inputStream.read()
        publicKeyAlgorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException(
                "PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported"
            )

        encryptedSessionKey = EncryptedSessionKey.getInstance(publicKeyAlgorithm).also {
            it.readFrom(inputStream)
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val encryptedSessionKeySnapshot = encryptedSessionKey
            ?: throw UnsupportedPublicKeyAlgorithmException("encryptedSessionKey must not be null.")

        outputStream.write(version)
        outputStream.write(keyId)
        outputStream.write(publicKeyAlgorithm.id)
        encryptedSessionKeySnapshot.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        return " * PacketPublicKeyEncryptedSessionKeyV3\n" +
                "   * Version: $version\n" +
                "   * keyId: ${keyId.toHex()}\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm.name}\n" +
                "   * encryptedSessionKey: ${encryptedSessionKey?.toDebugString()}\n" +
                ""
    }
}
