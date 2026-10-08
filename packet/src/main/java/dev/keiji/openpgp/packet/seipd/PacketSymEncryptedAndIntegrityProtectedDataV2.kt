@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.seipd

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAeadAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PacketSymEncryptedAndIntegrityProtectedDataV2 :
    PacketSymEncryptedAndIntegrityProtectedData() {

    companion object {
        const val VERSION = 2

        const val SALT_LENGTH = 32

        /**
         * An implementation MUST accept chunk size octets with values from 0 to 16.
         */
        const val MINIMUM_CHUNK_SIZE_OCTET = 0

        const val MAXIMUM_CHUNK_SIZE_OCTET = 16
    }

    override val version: Int = VERSION

    var cipherAlgorithm: SymmetricKeyAlgorithm? = null
    var aeadAlgorithm: AeadAlgorithm? = null

    private var _chunkSize: Int = -1

    /**
     * The chunk size octet. An implementation MUST accept chunk size
     * octets with values from 0 to 16.
     */
    var chunkSize: Int
        get() = _chunkSize
        set(value) {
            require(value in MINIMUM_CHUNK_SIZE_OCTET..MAXIMUM_CHUNK_SIZE_OCTET) {
                "chunk size octet must be $MINIMUM_CHUNK_SIZE_OCTET to " +
                        "$MAXIMUM_CHUNK_SIZE_OCTET but $value"
            }
            _chunkSize = value
        }

    /**
     * The chunk size in octets, that is, (1 << (chunkSize + 6)).
     */
    val chunkSizeInOctets: Long
        get() = 1L shl (_chunkSize + 6)

    var salt: ByteArray = ByteArray(SALT_LENGTH)

    var encryptedDataAndTag: ByteArray = byteArrayOf()

    var authenticationTag: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        val cipherAlgorithmByte = inputStream.read()
        cipherAlgorithm = SymmetricKeyAlgorithm.findBy(cipherAlgorithmByte)

        val aeadAlgorithmByte = inputStream.read()
        val aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte).also {
            aeadAlgorithm = it
        }
            ?: throw UnsupportedAeadAlgorithmException("aeadAlgorithm ID $aeadAlgorithmByte is not supported")

        chunkSize = inputStream.read()

        inputStream.read(salt)

        val encryptedDataFullBytes = inputStream.readBytes()

        encryptedDataAndTag = encryptedDataFullBytes.copyOfRange(
            0,
            encryptedDataFullBytes.size - aeadAlgorithm.tagLength
        )
        authenticationTag = encryptedDataFullBytes.copyOfRange(
            encryptedDataAndTag.size,
            encryptedDataFullBytes.size
        )
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val cipherAlgorithmSnapshot = cipherAlgorithm
            ?: throw InvalidParameterException("`cipherAlgorithm` must not be null.")
        val aeadAlgorithmSnapshot =
            aeadAlgorithm ?: throw InvalidParameterException("`aeadAlgorithm` must not be null.")

        outputStream.write(version)
        outputStream.write(cipherAlgorithmSnapshot.id)
        outputStream.write(aeadAlgorithmSnapshot.id)
        outputStream.write(chunkSize)
        outputStream.write(salt)

        outputStream.write(encryptedDataAndTag)

        outputStream.write(authenticationTag)
    }

    override fun toDebugString(): String {
        return " * PacketSymEncryptedAndIntegrityProtectedDataV2\n" +
                "   * Version: $version\n" +
                "   * cipherAlgorithm: ${cipherAlgorithm?.name}\n" +
                "   * aeadAlgorithm: ${aeadAlgorithm?.name}\n" +
                "   * chunkSize: ${chunkSize}(value: ${_chunkSize})\n" +
                "   * salt: ${salt.toHex()}\n" +
                "   * encryptedDataAndTag: ${encryptedDataAndTag.toHex()}\n" +
                "   * authenticationTag: ${authenticationTag.toHex()}\n" +
                ""
    }
}
