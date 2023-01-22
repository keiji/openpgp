package dev.keiji.openpgp.packet.userattribute.subpacket.image

import dev.keiji.openpgp.ImageType
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class ImageV1Header(length: Int) : ImageHeader(length) {
    companion object {
        const val VERSION = 1
    }

    override val version: Int = VERSION
    override val contentLength: Int
        get() {
            return (
                    length
                            - 2 // length bytes
                            - 1 // version byte
                    )
        }

    var imageType: ImageType? = null

    override fun readContentFrom(inputStream: InputStream) {
        val contentInputStream = ByteArray(contentLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        val imageTypeId = contentInputStream.read()
        imageType = ImageType.findBy(imageTypeId)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val imageTypeSnapshot = imageType ?: throw InvalidParameterException("`imageType` must not be null.")
        outputStream.write(imageTypeSnapshot.id)
    }

    override fun toDebugString(): String {
        return """
 * Version: $version
 * imageType: ${imageType?.name}
        """.trimIndent()
    }
}
