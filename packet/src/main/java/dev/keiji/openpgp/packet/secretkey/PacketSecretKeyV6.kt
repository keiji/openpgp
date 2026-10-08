@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAeadAlgorithmException
import dev.keiji.openpgp.UnsupportedS2KUsageTypeException
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV6
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * A version 6 Secret Key packet.
 *
 * The layout of the S2K parameter fields differs from a version 4 packet:
 * a version 6 packet prepends a 1-octet count of the cumulative length of
 * all the conditionally included S2K parameter fields, and (for the S2K
 * usage octets 253 and 254) a 1-octet count of the size of the S2K
 * Specifier field.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.3
 */
open class PacketSecretKeyV6 : PacketPublicKeyV6() {
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
     *
     * A version 6 packet where the S2K usage octet is zero has no trailing
     * 2-octet checksum, unlike a version 3 or 4 packet.
     */
    var data: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val string2keyUsageByte = inputStream.read()
        string2keyUsage = SecretKeyEncryptionType.findBy(string2keyUsageByte)
            ?: throw UnsupportedS2KUsageTypeException("S2KUsageType $string2keyUsageByte is not supported.")

        if (string2keyUsage != SecretKeyEncryptionType.ClearText) {
            readS2kParameterFields(inputStream)
        }

        data = inputStream.readBytes()
    }

    private fun readS2kParameterFields(inputStream: InputStream) {
        val s2kParameterFieldsLength = inputStream.read()
        val s2kParameterFields = ByteArray(s2kParameterFieldsLength).also {
            inputStream.read(it)
        }
        val s2kParameterFieldsInputStream = ByteArrayInputStream(s2kParameterFields)

        when (string2keyUsage) {
            SecretKeyEncryptionType.AEAD -> {
                readCipherAlgorithmFrom(s2kParameterFieldsInputStream)

                val aeadAlgorithmByte = s2kParameterFieldsInputStream.read()
                aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)
                    ?: throw UnsupportedAeadAlgorithmException(
                        "AeadAlgorithm $aeadAlgorithmByte is not supported."
                    )
            }

            SecretKeyEncryptionType.SHA1,
            SecretKeyEncryptionType.CheckSum,
            -> readCipherAlgorithmFrom(s2kParameterFieldsInputStream)

            else -> {
                // The S2K usage octet is a known symmetric cipher algorithm ID.
                // Only an initialization vector follows.
            }
        }

        if (string2keyUsage == SecretKeyEncryptionType.AEAD ||
            string2keyUsage == SecretKeyEncryptionType.SHA1
        ) {
            val string2KeyFieldLength = s2kParameterFieldsInputStream.read()
            val string2KeyField = ByteArray(string2KeyFieldLength).also {
                s2kParameterFieldsInputStream.read(it)
            }
            string2Key = String2KeyParser.parse(ByteArrayInputStream(string2KeyField))
        } else if (string2keyUsage == SecretKeyEncryptionType.CheckSum) {
            string2Key = String2KeyParser.parse(s2kParameterFieldsInputStream)
        }

        initializationVector = s2kParameterFieldsInputStream.readBytes()
    }

    private fun readCipherAlgorithmFrom(inputStream: ByteArrayInputStream) {
        val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
        symmetricKeyEncryptionAlgorithm =
            SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                ?: throw UnsupportedSymmetricKeyAlgorithmException(
                    "SymmetricKeyAlgorithm $symmetricKeyEncryptionAlgorithmByte is not supported."
                )
    }

    override fun writeContentTo(outputStream: OutputStream) {
        if (string2keyUsage == SecretKeyEncryptionType.CheckSum) {
            throw UnsupportedS2KUsageTypeException(
                "A version 6 packet MUST NOT use the S2K usage octet 255 (MalleableCFB)."
            )
        }

        super.writeContentTo(outputStream)

        outputStream.write(string2keyUsage.id)

        if (string2keyUsage != SecretKeyEncryptionType.ClearText) {
            writeS2kParameterFields(outputStream)
        }

        outputStream.write(data)
    }

    private fun writeS2kParameterFields(outputStream: OutputStream) {
        val s2kParameterFieldsOutputStream = ByteArrayOutputStream()

        when (string2keyUsage) {
            SecretKeyEncryptionType.AEAD -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException(
                        "symmetricKeyEncryptionAlgorithm must not be null."
                    )
                val aeadAlgorithmSnapshot = aeadAlgorithm
                    ?: throw InvalidParameterException("aeadAlgorithm must not be null.")

                s2kParameterFieldsOutputStream.write(symmetricKeyEncryptionAlgorithmSnapshot.id)
                s2kParameterFieldsOutputStream.write(aeadAlgorithmSnapshot.id)
            }

            SecretKeyEncryptionType.SHA1 -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException(
                        "symmetricKeyEncryptionAlgorithm must not be null."
                    )

                s2kParameterFieldsOutputStream.write(symmetricKeyEncryptionAlgorithmSnapshot.id)
            }

            else -> {
                // The S2K usage octet is a known symmetric cipher algorithm ID.
                // Only an initialization vector follows.
            }
        }

        if (string2keyUsage == SecretKeyEncryptionType.AEAD ||
            string2keyUsage == SecretKeyEncryptionType.SHA1
        ) {
            val string2KeySnapshot = string2Key
                ?: throw InvalidParameterException("string2Key must not be null.")

            val string2KeyFieldBytes = ByteArrayOutputStream().let {
                string2KeySnapshot.writeTo(it)
                it.toByteArray()
            }

            s2kParameterFieldsOutputStream.write(string2KeyFieldBytes.size)
            s2kParameterFieldsOutputStream.write(string2KeyFieldBytes)
        }

        val initializationVectorSnapshot = initializationVector
            ?: throw InvalidParameterException("initializationVector must not be null.")
        s2kParameterFieldsOutputStream.write(initializationVectorSnapshot)

        val s2kParameterFields = s2kParameterFieldsOutputStream.toByteArray()
        outputStream.write(s2kParameterFields.size)
        outputStream.write(s2kParameterFields)
    }

    override fun toDebugString(): String {
        return """
 * PacketSecretKeyV6
    * Version: $version
    * Algorithm: ${algorithm.name}
    * S2K Usage: ${string2keyUsage.id}
    * PublicKey:
    ${publicKey?.toString()}
    * data: ${data.size} octets
        """.trimIndent()
    }
}
