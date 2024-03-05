package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

/**
 * Symmetrically Encrypted Data Packet (Tag 9).
 *
 * This packet is obsolete.
 * An implementation MUST NOT create this packet.
 * An implementation MAY process such a packet, but it MUST return a clear diagnostic
 * that a non-integrity protected packet has been processed.
 * The implementation SHOULD also return an error in this case and stop processing.
 */
@Deprecated("This packet is obsolete.")
class PacketSymmetricallyEncryptedData : Packet() {
    override val tagValue: Int = Tag.SymmetricallyEncryptedDataPacket.value

    var data: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        // Do nothing.
//        data = inputStream.readBytes()
    }

    override fun writeTo(isLegacyFormat: Boolean, outputStream: OutputStream) {
        // Do nothing.
//        super.writeTo(isOld, outputStream)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        // Do nothing.
//        outputStream.write(data)
    }

    override fun toDebugString(): String = """
 * PacketSymmetricallyEncryptedData
   * data: ${data.toHex("")}
    """.trimIndent()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketSymmetricallyEncryptedData

        if (tagValue != other.tagValue) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tagValue
        result = 31 * result + data.contentHashCode()
        return result
    }
}
