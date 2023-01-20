package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.toUnsignedInt
import java.io.InputStream
import java.io.OutputStream

class PreferredHashAlgorithms : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredHashAlgorithms.value

    var ids: List<HashAlgorithm> = emptyList()

    override fun readFrom(inputStream: InputStream) {
        val values = inputStream.readBytes()
        ids = values.map {
            HashAlgorithm.findBy(it.toUnsignedInt())
                ?: throw UnsupportedHashAlgorithmException("ID $it is not supported.")
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        ids.forEach { id ->
            outputStream.write(id.id)
        }
    }

    override fun toDebugString(): String {
        return " * PreferredHashAlgorithms\n" +
                "   * ids: ${ids.map { it.toString() }.joinToString(", ")}\n" +
                ""
    }
}
