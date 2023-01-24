package dev.keiji.openpgp.packet

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.StringReader
import java.math.BigInteger

abstract class Packet {
    abstract val tagValue: Int

    val tag: Tag?
        get() = Tag.findBy(tagValue)

    abstract fun readContentFrom(inputStream: InputStream)

    fun writeTo(isOld: Boolean, outputStream: OutputStream) {
        val values = ByteArrayOutputStream().let { baos ->
            writeContentTo(baos)
            baos.toByteArray()
        }
        val length = values.size

        val header = PacketHeader().also { packetHeader ->
            packetHeader.isOld = isOld
            packetHeader.length = BigInteger.valueOf(length.toLong())
            packetHeader.tagValue = tagValue
        }

        header.writeTo(outputStream)
        outputStream.write(values)
    }

    abstract fun writeContentTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n")
        }
    }
}
