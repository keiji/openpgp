package dev.keiji.openpgp.packet.pkesk

import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.UnsupportedVersionException
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV6
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

/**
 * A version 6 Public Key Encrypted Session Key packet.
 *
 * A v6 PKESK packet precedes a v2 SEIPD packet. It consists of:
 *
 *  -  a 1-octet version number with value 6,
 *  -  a 1-octet size of the following two fields, which may be zero for
 *     an anonymous recipient,
 *  -  a 1-octet key version number,
 *  -  the fingerprint of the public key to which the session key is
 *     encrypted (20 octets for a version 4 key, 32 octets for a
 *     version 6 key),
 *  -  a 1-octet public key algorithm, and
 *  -  the algorithm-specific encrypted session key.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.2
 */
class PacketPublicKeyEncryptedSessionKeyV6 : PacketPublicKeyEncryptedSessionKey() {
    companion object {
        const val VERSION: Int = 6

        const val FINGERPRINT_LENGTH_V4 = 20

        const val FINGERPRINT_LENGTH_V6 = 32
    }

    override val version: Int = VERSION

    var keyVersion: Int = PacketPublicKeyV6.VERSION

    var fingerprint: ByteArray? = null

    var publicKeyAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.X25519

    var encryptedSessionKey: EncryptedSessionKey? = null

    override fun readContentFrom(inputStream: InputStream) {
        val fingerprintFieldSize = inputStream.read()

        if (fingerprintFieldSize == 0) {
            // Anonymous recipient: the key version number and the
            // fingerprint are omitted.
            keyVersion = -1
            fingerprint = null
        } else {
            val keyVersionByte = inputStream.read()
            keyVersion = keyVersionByte

            val fingerprintLength = when (keyVersionByte) {
                PacketPublicKeyV4.VERSION -> FINGERPRINT_LENGTH_V4
                PacketPublicKeyV6.VERSION -> FINGERPRINT_LENGTH_V6
                else -> throw UnsupportedVersionException(
                    "Key version $keyVersionByte is not supported."
                )
            }

            if (fingerprintLength != fingerprintFieldSize - 1) {
                throw UnsupportedVersionException(
                    "Fingerprint field size $fingerprintFieldSize does not match " +
                            "the fingerprint length $fingerprintLength of a version " +
                            "$keyVersionByte key."
                )
            }

            fingerprint = ByteArray(fingerprintLength).also {
                inputStream.read(it)
            }
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

        val fingerprintSnapshot = fingerprint
        if (fingerprintSnapshot == null) {
            // Anonymous recipient.
            outputStream.write(0)
        } else {
            outputStream.write(1 + fingerprintSnapshot.size)
            outputStream.write(keyVersion)
            outputStream.write(fingerprintSnapshot)
        }

        outputStream.write(publicKeyAlgorithm.id)
        encryptedSessionKeySnapshot.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        return " * PacketPublicKeyEncryptedSessionKeyV6\n" +
                "   * Version: $version\n" +
                "   * keyVersion: $keyVersion\n" +
                "   * fingerprint: ${fingerprint?.toHex()}\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm.name}\n" +
                "   * encryptedSessionKey: ${encryptedSessionKey?.toDebugString()}\n" +
                ""
    }
}
