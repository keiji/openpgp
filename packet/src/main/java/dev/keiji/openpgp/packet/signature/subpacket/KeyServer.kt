package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class KeyServer : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredKeyServer.value

    var uri: String? = null

    override fun readFrom(inputStream: InputStream) {
        val values = inputStream.readBytes()
        uri = String(values, charset = Charsets.US_ASCII)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        uri?.also {
            outputStream.write(it.toByteArray(charset = Charsets.US_ASCII))
        }
    }

    override fun toDebugString(): String {
        return " * KeyServer\n" +
                "   * uri: $uri\n" +
                ""
    }
}
