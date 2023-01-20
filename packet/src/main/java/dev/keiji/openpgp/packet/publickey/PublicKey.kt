package dev.keiji.openpgp.packet.publickey

import java.io.InputStream
import java.io.OutputStream
import java.io.StringReader

abstract class PublicKey {
    abstract fun readFrom(inputStream: InputStream)
    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n") { line -> "  $line" }
        }
    }
}
