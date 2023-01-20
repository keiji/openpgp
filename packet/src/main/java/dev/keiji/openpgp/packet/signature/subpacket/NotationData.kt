package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.to2ByteArray
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toInt
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

    override fun readFrom(inputStream: InputStream) {
        inputStream.read(flags)

        while (inputStream.available() > 0) {
            val nameLengthBytes = ByteArray(2)
            inputStream.read(nameLengthBytes)
            val nameLength = nameLengthBytes.toInt()

            val nameBytes = ByteArray(nameLength)
            inputStream.read(nameBytes)

            val valueLengthBytes = ByteArray(2)
            inputStream.read(valueLengthBytes)
            val valueLength = valueLengthBytes.toInt()

            val valueBytes = ByteArray(valueLength)
            inputStream.read(valueBytes)

            val name = String(nameBytes, StandardCharsets.UTF_8)
            val value = String(valueBytes, StandardCharsets.UTF_8)
            _map[name] = value
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        _map.keys.forEach { name ->
            val value = _map[name] ?: return@forEach

            val nameBytes = name.toByteArray(charset = Charsets.US_ASCII)
            val nameLengthBytes = nameBytes.size.to2ByteArray()

            val valueBytes = value.toByteArray(charset = Charsets.US_ASCII)
            val valueLengthBytes = valueBytes.size.to2ByteArray()

            outputStream.write(nameLengthBytes)
            outputStream.write(nameBytes)

            outputStream.write(valueLengthBytes)
            outputStream.write(valueBytes)
        }
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * KeyServer\n" +
                    "   * flags: ${flags.toHex("")}\n" +
                    ""
        )

        _map.keys.forEach { key ->
            _map[key]?.forEach { value ->
                sb.append("   * ${key}:${value}\n")
            }
        }

        return sb.toString()
    }
}
