package dev.keiji.openpgp.packet.secretkey

import java.io.InputStream
import java.io.OutputStream

abstract class SecretKey {
    abstract fun readFrom(inputStream: InputStream)
    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String
}
