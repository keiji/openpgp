package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.String2KeyType
import java.io.InputStream
import java.io.OutputStream

abstract class String2Key {

    abstract val type: String2KeyType
    abstract val length: Int

    abstract fun readFrom(inputStream: InputStream)
    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String
}
