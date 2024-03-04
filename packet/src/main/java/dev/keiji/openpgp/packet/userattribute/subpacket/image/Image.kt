package dev.keiji.openpgp.packet.userattribute.subpacket.image

import dev.keiji.openpgp.packet.userattribute.subpacket.Subpacket
import dev.keiji.openpgp.packet.userattribute.subpacket.SubpacketType
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class Image : Subpacket() {
    override val typeValue: Int = SubpacketType.Image.value

    var header: ImageHeader? = null
    var imageData: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        header = ImageHeaderDecoder.decode(inputStream)
        imageData = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        // Do nothing
    }

    override fun toDebugString(): String {
        val headerSnapshot = header ?: throw InvalidParameterException("`header` must not be null.")
        val imageDataSnapshot = imageData ?: throw InvalidParameterException("`imageData` must not be null.")

        return """
 * Image
    * Header
${headerSnapshot}
    * ${imageDataSnapshot.size} bytes
        """.trimIndent()
    }
}
