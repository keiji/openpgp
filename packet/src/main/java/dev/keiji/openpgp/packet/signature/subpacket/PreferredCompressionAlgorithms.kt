package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.UnsupportedCompressionAlgorithmException
import dev.keiji.openpgp.toUnsignedInt
import java.io.InputStream
import java.io.OutputStream

class PreferredCompressionAlgorithms : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredCompressionAlgorithms.value

    var ids: List<CompressionAlgorithm> = emptyList()

    override fun readFrom(inputStream: InputStream) {
        val values = inputStream.readBytes()
        ids = values.map {
            CompressionAlgorithm.findBy(it.toUnsignedInt())
                ?: throw UnsupportedCompressionAlgorithmException("ID $it is not supported.")
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        ids.forEach {
            outputStream.write(it.id)
        }
    }

    override fun toDebugString(): String {
        return " * PreferredCompressionAlgorithms\n" +
                "   * ids: ${ids.map { it.toString() }.joinToString(", ")}\n" +
                ""
    }
}
