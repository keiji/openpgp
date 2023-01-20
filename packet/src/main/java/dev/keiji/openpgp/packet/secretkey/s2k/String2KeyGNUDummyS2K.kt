package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class String2KeyGNUDummyS2K : String2Key() {
    override val type: String2KeyType = String2KeyType.GNU_DUMMY_S2K
    override val length: Int = 0

    var values: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        values = ByteArray(length).also {
            inputStream.read(it)
        }
        println("String2KeyGNUDummyS2K " + values.toHex(""))
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(type.id)
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return " * String2KeyGNUDummyS2K\n" +
                "   * values: ${values.toHex()}\n" +
                ""
    }
}
