@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.KdfUtils
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class String2KeySaltedIterated : String2Key() {
    override val type: String2KeyType = String2KeyType.SALTED_ITERATED
    override val length: Int = 11 - 1 // first byte - S2KType

    var hashAlgorithm: HashAlgorithm? = null
    var salt: ByteArray = ByteArray(8)

    private var _iterationCount: Long = 1
    var iterationCount: Long
        get() = KdfUtils.calculateIterationCount(_iterationCount)
        set(value) {
            _iterationCount = value
        }

    override fun readFrom(inputStream: InputStream) {
        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)

        inputStream.read(salt)

        _iterationCount = inputStream.read().toLong()
    }

    override fun writeTo(outputStream: OutputStream) {
        val hashAlgorithmSnapshot =
            hashAlgorithm ?: throw InvalidParameterException("`hashAlgorithm` must not be null.")

        outputStream.write(type.id)
        outputStream.write(hashAlgorithmSnapshot.id)
        outputStream.write(_iterationCount.toInt())
        outputStream.write(salt)
    }

    override fun toDebugString(): String {
        return " * String2KeySaltedIterated\n" +
                "   * hashAlgorithm: ${hashAlgorithm}\n" +
                "   * salt: ${salt.toHex()}\n" +
                "   * iterationCount: $_iterationCount(value: ${_iterationCount})\n" +
                ""
    }
}
