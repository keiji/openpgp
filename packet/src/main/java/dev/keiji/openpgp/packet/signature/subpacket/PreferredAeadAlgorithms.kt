package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.UnsupportedCompressionAlgorithmException
import dev.keiji.openpgp.toUnsignedInt
import java.io.InputStream
import java.io.OutputStream

class PreferredAeadAlgorithms : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredAeadAlgorithms.value

    var ids: List<AeadAlgorithm> = emptyList()

    override fun readFrom(inputStream: InputStream) {
        val values = inputStream.readBytes()
        ids = values.map {
            AeadAlgorithm.findBy(it.toUnsignedInt())
                ?: throw UnsupportedCompressionAlgorithmException("ID $it is not supported.")
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        ids.forEach {
            outputStream.write(it.id)
        }
    }

    override fun toDebugString(): String {
        return " * PreferredAeadAlgorithms\n" +
                "   * ids: ${ids.map { it.toString() }.joinToString(", ")}\n" +
                ""
    }
}
