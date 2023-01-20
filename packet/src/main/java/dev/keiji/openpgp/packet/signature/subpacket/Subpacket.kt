package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.UnsupportedSubpacketTypeException
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

    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n") { line -> "  $line" } + "\n"
        }
    }
}
