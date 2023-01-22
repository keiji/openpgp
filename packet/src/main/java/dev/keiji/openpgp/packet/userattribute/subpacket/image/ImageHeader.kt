package dev.keiji.openpgp.packet.userattribute.subpacket.image

import dev.keiji.openpgp.toUnsignedInt
import java.io.InputStream
import java.io.OutputStream
import java.io.StringReader

abstract class ImageHeader(
    var length: Int = 0,
) {
    abstract val version: Int

    abstract val contentLength: Int

    abstract fun readContentFrom(inputStream: InputStream)

    abstract fun writeContentTo(outputStream: OutputStream)

    override fun toString(): String {
        val str = toDebugString()
        return StringReader(str).use {
            it.readLines().joinToString("\n") { line -> "  $line" } + "\n"
        }
    }

    abstract fun toDebugString(): String

    companion object {
        /**
         * Note that unlike other multi-octet numeical values in this document,
         * due to a historical accident this value is encoded as a little-endian number.
         */
        internal fun convertBytesToLength(lengthBytes: ByteArray): Int {
            if (lengthBytes.size != 2) {
                throw IllegalArgumentException("lengthBytes must be 2 bytes.")
            }

            return lengthBytes[0].toUnsignedInt() or
                    (lengthBytes[1].toUnsignedInt() shl Byte.SIZE_BITS)

        }
    }
}
