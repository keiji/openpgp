@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.to2ByteArray
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toInt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder
import java.nio.charset.StandardCharsets

class NotationData : Subpacket() {
    override val typeValue: Int = SubpacketType.NotationData.value

    var flags: ByteArray = ByteArray(4)

    private val _map: MutableMap<String, String> = mutableMapOf()
    val map: Map<String, String>
        get() = _map

    /**
     * The raw content octets of this subpacket: the 4-octet flags
     * followed by the name/value pairs. The raw octets are preserved
     * for byte-exact re-encoding.
     */
    var values: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        values = inputStream.readBytes()

        val contentStream = ByteArrayInputStream(values)
        contentStream.read(flags)

        while (contentStream.available() > 0) {
            val nameLengthBytes = ByteArray(2)
            contentStream.read(nameLengthBytes)
            val nameLength = nameLengthBytes.toInt()

            val nameBytes = ByteArray(nameLength)
            contentStream.read(nameBytes)

            val valueLengthBytes = ByteArray(2)
            contentStream.read(valueLengthBytes)
            val valueLength = valueLengthBytes.toInt()

            val valueBytes = ByteArray(valueLength)
            contentStream.read(valueBytes)

            val name = String(nameBytes, StandardCharsets.UTF_8)
            val value = String(valueBytes, StandardCharsets.UTF_8)
            _map[name] = value
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * NotationData\n" +
                    "   * flags: ${flags.toHex("")}\n" +
                    ""
        )

        _map.keys.forEach { key ->
            sb.append("   * $key:${_map[key]}\n")
        }

        return sb.toString()
    }

    companion object {
        fun getInstance(
            flags: ByteArray,
            name: String,
            value: String,
        ): NotationData {
            val nameBytes = name.toByteArray(charset = StandardCharsets.UTF_8)
            val valueBytes = value.toByteArray(charset = StandardCharsets.UTF_8)

            val values = ByteArrayOutputStream().let { baos ->
                baos.write(flags)
                baos.write(nameBytes.size.to2ByteArray())
                baos.write(nameBytes)
                baos.write(valueBytes.size.to2ByteArray())
                baos.write(valueBytes)
                baos.toByteArray()
            }

            return NotationData().also {
                it.values = values
                it.readFrom(ByteArrayInputStream(values))
            }
        }
    }
}
