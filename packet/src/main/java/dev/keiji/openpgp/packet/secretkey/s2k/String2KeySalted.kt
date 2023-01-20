package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class String2KeySalted : String2Key() {
    override val type: String2KeyType = String2KeyType.SALTED
    override val length: Int = 10 - 1 // first byte - S2KType

    var hashAlgorithm: HashAlgorithm? = null
    var salt: ByteArray = ByteArray(8)

    override fun readFrom(inputStream: InputStream) {
        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
        inputStream.read(salt)
    }

    override fun writeTo(outputStream: OutputStream) {
        val hashAlgorithmSnapshot =
            hashAlgorithm ?: throw InvalidParameterException("`hashAlgorithm` must not be null.")

        outputStream.write(type.id)
        outputStream.write(hashAlgorithmSnapshot.id)
        outputStream.write(salt)
    }

    override fun toDebugString(): String {
        return " * String2KeySaltedIterated\n" +
                "   * hashAlgorithm: ${hashAlgorithm}\n" +
                "   * salt: ${salt.toHex()}\n" +
                ""
    }
}
