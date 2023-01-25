package dev.keiji.openpgp.packet.userattribute.subpacket.image

import dev.keiji.openpgp.UnsupportedUserAttributeImageVersionException
import java.io.ByteArrayInputStream
import java.io.InputStream

object ImageHeaderDecoder {

    fun decode(inputStream: InputStream): ImageHeader {
        val lengthBytes = ByteArray(2).also {
            inputStream.read(it)
        }
        val length = ImageHeader.convertBytesToLength(lengthBytes)
        val version = inputStream.read()

        return when (version) {
            1 -> ImageV1Header(length).also {
                it.readContentFrom(inputStream)
            }

            else -> throw UnsupportedUserAttributeImageVersionException("Image version $version is not supported.")
        }
    }
}
