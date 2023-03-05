package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.UnsupportedSubpacketTypeException
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.StringReader

abstract class Subpacket {
    abstract val typeValue: Int

    fun getType(default: SubpacketType? = null): SubpacketType {
        val subpacketType = SubpacketType.findBy(typeValue)
        if (subpacketType != null) {
            return subpacketType
        }
        if (default != null) {
            return default
        }
        throw UnsupportedSubpacketTypeException("Subpacket type $typeValue is not supported.")
    }

    abstract fun readFrom(inputStream: InputStream)

    fun writeTo(outputStream: OutputStream) {
        val contentBytes = ByteArrayOutputStream().let {
            writeContentTo(it)
            it.toByteArray()
        }

        val header = SubpacketHeader().also {
            // The length includes the type-octet but not length-octets.
            it.length = contentBytes.size + 1
            it.typeValue = getType().value
            it.isCriticalBit = false
        }
        header.writeTo(outputStream)
        outputStream.write(contentBytes)
    }

    abstract fun writeContentTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n") { line -> "    $line" } + "\n"
        }
    }
}
