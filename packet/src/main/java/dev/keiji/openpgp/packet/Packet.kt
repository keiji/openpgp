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

    /**
     * The packet header format this packet was decoded from.
     * When re-encoding a decoded packet without an explicit format,
     * this preserves the original framing.
     */
    var isLegacyFormat: Boolean = false

    /**
     * The Packet Type ID this packet was decoded from, when it differs
     * from the canonical Type ID of the packet (for example, an
     * AEAD-encrypted data packet decoded with the reserved Type ID 20
     * in place of the SEIPD Type ID 18). When re-encoding, this
     * preserves the original framing.
     */
    var tagValueOverride: Int? = null

    abstract fun readContentFrom(inputStream: InputStream)

    open fun writeTo(isLegacyFormat: Boolean, outputStream: OutputStream) {
        val values = ByteArrayOutputStream().let { baos ->
            writeContentTo(baos)
            baos.toByteArray()
        }
        val length = values.size

        val header = PacketHeader().also { packetHeader ->
            packetHeader.isLegacyFormat = isLegacyFormat
            packetHeader.length = BigInteger.valueOf(length.toLong())
            packetHeader.tagValue = tagValueOverride ?: tagValue
        }

        header.writeTo(outputStream)
        outputStream.write(values)
    }

    fun writeTo(outputStream: OutputStream) {
        writeTo(isLegacyFormat, outputStream)
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
