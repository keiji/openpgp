@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAeadAlgorithmException
import dev.keiji.openpgp.UnsupportedS2KUsageTypeException
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * A version 4 Secret Key packet.
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.3
 */
open class PacketSecretKeyV4 : PacketPublicKeyV4() {
    override val tagValue: Int = Tag.SecretKey.value

    var string2keyUsage: SecretKeyEncryptionType = SecretKeyEncryptionType.ClearText

    var symmetricKeyEncryptionAlgorithm: SymmetricKeyAlgorithm? = null

    var aeadAlgorithm: AeadAlgorithm? = null

    var string2Key: String2Key? = null

    /**
     * An initialization vector used as the nonce for the AEAD algorithm
     * (when the S2K usage octet is 253), or an initialization vector of
     * the same length as the cipher's block size (when the S2K usage
     * octet indicates CFB encryption).
     */
    var initializationVector: ByteArray? = null

    /**
     * Plain or encrypted multiprecision integers comprising the secret
     * key data, including the trailing AEAD tag, SHA-1 hash or 2-octet
     * checksum when the secret key material is protected by a passphrase.
     * For a version 4 packet where the S2K usage octet is zero, this
     * includes the trailing 2-octet checksum of the cleartext.
     */
    var data: ByteArray? = null

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val string2keyUsageByte = inputStream.read()
        string2keyUsage = SecretKeyEncryptionType.findBy(string2keyUsageByte)
            ?: throw UnsupportedS2KUsageTypeException("S2KUsageType $string2keyUsageByte is not supported.")

        when (string2keyUsage) {
            SecretKeyEncryptionType.ClearText -> {
                // No S2K parameter fields follow.
            }

            SecretKeyEncryptionType.AEAD -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                        ?: throw UnsupportedSymmetricKeyAlgorithmException(
                            "SymmetricKeyAlgorithm $symmetricKeyEncryptionAlgorithmByte is not supported."
                        )

                val aeadAlgorithmByte = inputStream.read()
                aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)
                    ?: throw UnsupportedAeadAlgorithmException(
                        "AeadAlgorithm $aeadAlgorithmByte is not supported."
                    )

                string2Key = String2KeyParser.parse(inputStream)

                val aeadAlgorithmSnapshot = aeadAlgorithm
                    ?: throw UnsupportedAeadAlgorithmException("AeadAlgorithm must not be null.")
                initializationVector = ByteArray(aeadAlgorithmSnapshot.nonceLength).also {
                    inputStream.read(it)
                }
            }

            SecretKeyEncryptionType.SHA1 -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                        ?: throw UnsupportedSymmetricKeyAlgorithmException(
                            "SymmetricKeyAlgorithm $symmetricKeyEncryptionAlgorithmByte is not supported."
                        )

                string2Key = String2KeyParser.parse(inputStream)

                initializationVector = readInitializationVectorOfCipherBlockSize(inputStream)
            }

            SecretKeyEncryptionType.CheckSum -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                        ?: throw UnsupportedSymmetricKeyAlgorithmException(
                            "SymmetricKeyAlgorithm $symmetricKeyEncryptionAlgorithmByte is not supported."
                        )

                string2Key = String2KeyParser.parse(inputStream)

                initializationVector = readInitializationVectorOfCipherBlockSize(inputStream)
            }

            else -> {
                // The S2K usage octet is a known symmetric cipher algorithm ID.
                // Only an initialization vector follows.
                initializationVector = readInitializationVectorOfCipherBlockSize(inputStream)
            }
        }

        data = inputStream.readBytes()
    }

    private fun readInitializationVectorOfCipherBlockSize(inputStream: InputStream): ByteArray {
        val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
            ?: throw UnsupportedSymmetricKeyAlgorithmException(
                "SymmetricKeyAlgorithm must not be null."
            )
        return ByteArray(symmetricKeyEncryptionAlgorithmSnapshot.blockLength).also {
            inputStream.read(it)
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        super.writeContentTo(outputStream)

        outputStream.write(string2keyUsage.id)

        when (string2keyUsage) {
            SecretKeyEncryptionType.ClearText -> {
                // No S2K parameter fields follow.
            }

            SecretKeyEncryptionType.AEAD -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException(
                        "symmetricKeyEncryptionAlgorithm must not be null."
                    )
                val aeadAlgorithmSnapshot = aeadAlgorithm
                    ?: throw InvalidParameterException("aeadAlgorithm must not be null.")
                val string2KeySnapshot = string2Key
                    ?: throw InvalidParameterException("string2Key must not be null.")
                val initializationVectorSnapshot = initializationVector
                    ?: throw InvalidParameterException("initializationVector must not be null.")

                outputStream.write(symmetricKeyEncryptionAlgorithmSnapshot.id)
                outputStream.write(aeadAlgorithmSnapshot.id)
                string2KeySnapshot.writeTo(outputStream)
                outputStream.write(initializationVectorSnapshot)
            }

            SecretKeyEncryptionType.SHA1,
            SecretKeyEncryptionType.CheckSum,
            -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException(
                        "symmetricKeyEncryptionAlgorithm must not be null."
                    )
                val string2KeySnapshot = string2Key
                    ?: throw InvalidParameterException("string2Key must not be null.")
                val initializationVectorSnapshot = initializationVector
                    ?: throw InvalidParameterException("initializationVector must not be null.")

                outputStream.write(symmetricKeyEncryptionAlgorithmSnapshot.id)
                string2KeySnapshot.writeTo(outputStream)
                outputStream.write(initializationVectorSnapshot)
            }

            else -> {
                // The S2K usage octet is a known symmetric cipher algorithm ID.
                val initializationVectorSnapshot = initializationVector
                    ?: throw InvalidParameterException("initializationVector must not be null.")
                outputStream.write(initializationVectorSnapshot)
            }
        }

        val dataSnapshot = data ?: throw InvalidParameterException("data must not be null.")
        outputStream.write(dataSnapshot)
    }

    override fun toDebugString(): String {
        return """
 * PacketSecretKeyV4
    * Version: $version
    * Algorithm: ${algorithm.name}
    * PublicKey:
    ${publicKey?.toString()}
        """.trimIndent()
    }
}
