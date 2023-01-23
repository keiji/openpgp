package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

class PacketMarker : Packet() {
    override val tagValue: Int = Tag.Marker.value

    var values: ByteArray = "PGP".toByteArray(charset = StandardCharsets.US_ASCII)

    override fun readFrom(inputStream: InputStream) {
        values = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return " * PacketMarker\n" +
                "   * ${values.toHex("")}\n"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketMarker

        if (tagValue != other.tagValue) return false
        if (!values.contentEquals(other.values)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tagValue
        result = 31 * result + values.contentHashCode()
        return result
    }
}
