package dev.keiji.openpgp.packet

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.UnsupportedCompressionAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PacketCompressedData : Packet() {
    override val tagValue: Int = Tag.CompressedData.value

    var compressionAlgorithm: CompressionAlgorithm? = null
    var data: ByteArray = byteArrayOf()

    val rawDataInputStream: InputStream
        get() {
            val compressionAlgorithmSnapshot =
                compressionAlgorithm ?: throw UnsupportedCompressionAlgorithmException("")
            return compressionAlgorithmSnapshot.getInputStream(ByteArrayInputStream(data))
        }

    override fun readContentFrom(inputStream: InputStream) {
        val compressionAlgorithmByte = inputStream.read()
        compressionAlgorithm = CompressionAlgorithm.findBy(compressionAlgorithmByte)

        data = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val compressionAlgorithmSnapshot =
            compressionAlgorithm ?: throw InvalidParameterException("`compressionAlgorithm` must not be null.")

        outputStream.write(compressionAlgorithmSnapshot.id)
        outputStream.write(data)
    }

    override fun toDebugString(): String {
        return """
* PacketCompressedData
   * compressionAlgorithm: ${compressionAlgorithm}
   * data(${data.size} bytes): ${data.toHex("")}
        """.trimIndent()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketCompressedData

        if (tagValue != other.tagValue) return false
        if (compressionAlgorithm != other.compressionAlgorithm) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tagValue
        result = 31 * result + (compressionAlgorithm?.hashCode() ?: 0)
        result = 31 * result + data.contentHashCode()
        return result
    }

}
