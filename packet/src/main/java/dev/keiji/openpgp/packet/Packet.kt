package dev.keiji.openpgp.packet

import java.io.InputStream
import java.io.OutputStream
import java.io.StringReader

abstract class Packet {
    abstract val tagValue: Int

    val tag: Tag?
        get() = Tag.findBy(tagValue)

    abstract fun readFrom(inputStream: InputStream)

    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n")
        }
    }
}
