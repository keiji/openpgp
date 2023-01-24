package dev.keiji.openpgp.packet

import java.io.InputStream
import java.io.OutputStream

class PacketUserId : Packet() {
    override val tagValue: Int = Tag.UserId.value

    var userId: String = ""

    override fun readContentFrom(inputStream: InputStream) {
        val userIdBytes = inputStream.readBytes()
        userId = String(userIdBytes, Charsets.US_ASCII)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(userId.toByteArray(charset = Charsets.US_ASCII))
    }

    override fun toDebugString(): String {
        return " * PacketUserId\n" +
                "   * $userId\n"
    }
}
