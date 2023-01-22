package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class PrimaryUserId : Subpacket() {
    override val typeValue: Int = SubpacketType.PrimaryUserId.value

    var flag: Boolean = false

    override fun readFrom(inputStream: InputStream) {
        flag = inputStream.read() != 0
    }

    override fun writeContentTo(outputStream: OutputStream) {
        if (flag) {
            outputStream.write(1)
        } else {
            outputStream.write(0)
        }
    }

    override fun toDebugString(): String {
        return " * PrimaryUserId\n" +
                "   * flag: $flag\n" +
                ""
    }
}
