package dev.keiji.openpgp.packet.signature.subpacket

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

class SignersUserId : Subpacket() {
    override val typeValue: Int = SubpacketType.SignerUserId.value

    var userId: String? = null

    override fun readFrom(inputStream: InputStream) {
        val userIdBytes = inputStream.readBytes()
        userId = String(userIdBytes, StandardCharsets.UTF_8)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        userId?.also {
            outputStream.write(it.toByteArray(charset = Charsets.UTF_8))
        }
    }

    override fun toDebugString(): String {
        return " * SignersUserId\n" +
                "   * userId: $userId\n" +
                ""
    }
}
