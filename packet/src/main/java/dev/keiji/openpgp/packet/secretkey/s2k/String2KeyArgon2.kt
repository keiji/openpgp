package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class String2KeyArgon2 : String2Key() {
    override val type: String2KeyType = String2KeyType.ARGON2
    override val length: Int = 20 - 1 // first byte - S2KType

    val salt: ByteArray = ByteArray(16)
    var passes: Int = -1
    var parallelism: Int = -1
    var memorySizeExponent: Int = -1

    override fun readFrom(inputStream: InputStream) {
        println("String2KeyArgon2")

        inputStream.read(salt)
        passes = inputStream.read()
        parallelism = inputStream.read()
        memorySizeExponent = inputStream.read()
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(type.id)
        outputStream.write(salt)
        outputStream.write(passes)
        outputStream.write(parallelism)
        outputStream.write(memorySizeExponent)
    }

    override fun toDebugString(): String {
        return " * String2KeyArgon2\n" +
                "   * salt: ${salt.toHex()}\n" +
                "   * passes: $passes\n" +
                "   * parallelism: $parallelism\n" +
                "   * memorySizeExponent: $memorySizeExponent\n" +
                ""
    }
}
