package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

/**
 * Trust Packet (Tag 12).
 *
 * Trust packet is used only within keyrings and is not normally exported.
 * Trust packets SHOULD NOT be emitted to output streams that are transferred to other users,
 * and they SHOULD be ignored on any input other than local keyring file.
 */
class PacketTrust : Packet() {
    override val tagValue: Int = Tag.Trust.value

    var data: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        data = inputStream.readBytes()
    }

    override fun writeTo(isOld: Boolean, outputStream: OutputStream) {
        // Do nothing
//        super.writeTo(isOld, outputStream)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        // Do nothing
//        outputStream.write(data)
    }

    override fun toDebugString(): String {
        return " * PacketTrust\n" +
                "   * ${data.toHex("")}\n"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketTrust

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
