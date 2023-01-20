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
    }

    override val version: Int = VERSION

    var cipherAlgorithm: SymmetricKeyAlgorithm? = null
    var aeadAlgorithm: AeadAlgorithm? = null

    private var _chunkSize: Int = -1
    var chunkSize: Int
        get() = (1 shl (_chunkSize + 6))
        set(value) {
            _chunkSize = value
        }

    var salt: ByteArray = ByteArray(32)

    var encryptedDataAndTag: ByteArray = byteArrayOf()

    var authenticationTag: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
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

    override fun writeTo(outputStream: OutputStream) {
        val cipherAlgorithmSnapshot = cipherAlgorithm
            ?: throw InvalidParameterException("`cipherAlgorithm` must not be null.")
        val aeadAlgorithmSnapshot =
            aeadAlgorithm ?: throw InvalidParameterException("`aeadAlgorithm` must not be null.")

        outputStream.write(version)
        outputStream.write(cipherAlgorithmSnapshot.id)
        outputStream.write(aeadAlgorithmSnapshot.id)
        outputStream.write(_chunkSize)
        outputStream.write(salt)

        outputStream.write(encryptedDataAndTag)

        outputStream.write(authenticationTag)
    }

    override fun toDebugString(): String {
        return " * PacketSymEncryptedAndIntegrityProtectedDataV2\n" +
                "   * Version: $version\n" +
                "   * cipherAlgorithm: ${cipherAlgorithm?.id}\n" +
                "   * aeadAlgorithm: ${aeadAlgorithm?.id}\n" +
                "   * chunkSize: ${chunkSize}(value: ${_chunkSize})\n" +
                "   * salt: ${salt.toHex()}\n" +
                "   * encryptedDataAndTag: ${encryptedDataAndTag.toHex()}\n" +
                "   * authenticationTag: ${authenticationTag.toHex()}\n" +
                ""
    }
}
