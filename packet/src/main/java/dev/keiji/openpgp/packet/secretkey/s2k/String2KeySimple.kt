package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class String2KeySimple : String2Key() {
    override val type: String2KeyType = String2KeyType.SIMPLE
    override val length: Int = 2 - 1

    var hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA2_256

    override fun readFrom(inputStream: InputStream) {
        println("String2KeySimple")
        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
            ?: throw UnsupportedHashAlgorithmException("HashAlgorithm ${hashAlgorithmByte.toHex()} is unsupported.")
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(type.id)
        outputStream.write(hashAlgorithm.id)
    }

    override fun toDebugString(): String {
        return " * String2KeySimple\n" +
                "   * hashAlgorithm: $hashAlgorithm\n" +
                ""
    }
}
