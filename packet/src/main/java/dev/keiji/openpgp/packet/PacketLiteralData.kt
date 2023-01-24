package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toInt
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.InvalidParameterException

enum class LiteralDataFormat(
    val value: Int,
) {
    Binary('b'.code),
    Text('u'.code),

    /* @Deprecated */
    OldText('t'.code),

    /* @Deprecated */
    Local('l'.code),
    ;

    companion object {
        fun findBy(value: Int) = values().firstOrNull { it.value == value }
    }
}

class PacketLiteralData : Packet() {
    override val tagValue: Int = Tag.LiteralData.value

    var format: LiteralDataFormat? = null
    var fileName: String = ""
    var date: Int = -1
    var values: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        val formatValue = inputStream.read()
        format = LiteralDataFormat.findBy(formatValue)

        val fileNameLength = inputStream.read()
        fileName = ByteArray(fileNameLength).let {
            inputStream.read(it)
            String(it, charset = StandardCharsets.UTF_8)
        }

        date = ByteArray(4).let {
            inputStream.read(it)
            it.toInt()
        }

        values = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val formatSnapshot = format ?: throw InvalidParameterException("`format` must not be null.")

        outputStream.write(formatSnapshot.value)

        outputStream.write(fileName.length)
        outputStream.write(fileName.toByteArray(charset = StandardCharsets.UTF_8))

        outputStream.write(date.toByteArray())

        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return """
* PacketLiteralData
    * Format: ${format?.name}
    * FileName: $fileName
    * Date: $date
    * Values: ${values.toHex("")}
""".trimIndent()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketLiteralData

        if (tagValue != other.tagValue) return false
        if (format != other.format) return false
        if (fileName != other.fileName) return false
        if (date != other.date) return false
        if (!values.contentEquals(other.values)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tagValue
        result = 31 * result + (format?.hashCode() ?: 0)
        result = 31 * result + fileName.hashCode()
        result = 31 * result + date
        result = 31 * result + values.contentHashCode()
        return result
    }


}
