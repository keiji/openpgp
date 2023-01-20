package dev.keiji.openpgp.packet.signature.subpacket

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

class PolicyUri : Subpacket() {
    override val typeValue: Int = SubpacketType.PolicyUri.value

    var uri: String? = null

    override fun readFrom(inputStream: InputStream) {
        val uriBytes = inputStream.readBytes()
        uri = String(uriBytes, StandardCharsets.UTF_8)
    }

    override fun writeTo(outputStream: OutputStream) {
        uri?.also {
            outputStream.write(it.toByteArray(charset = Charsets.UTF_8))
        }
    }

    override fun toDebugString(): String {
        return " * PolicyUri\n" +
                "   * uri: $uri\n" +
                ""
    }
}
