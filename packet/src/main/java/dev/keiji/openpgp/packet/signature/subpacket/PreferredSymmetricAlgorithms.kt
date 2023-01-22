package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toUnsignedInt
import java.io.InputStream
import java.io.OutputStream

class PreferredSymmetricAlgorithms : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredSymmetricAlgorithms.value

    var ids: List<SymmetricKeyAlgorithm> = emptyList()

    override fun readFrom(inputStream: InputStream) {
        val values = inputStream.readBytes()
        ids = values.map { SymmetricKeyAlgorithm.findBy(it.toUnsignedInt()) }.filterNotNull()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        ids.forEach { id ->
            outputStream.write(id.id)
        }
    }

    override fun toDebugString(): String {
        return " * PreferredSymmetricAlgorithms\n" +
                "   * ids: ${ids.map { it.name }.joinToString(", ")}\n" +
                ""
    }
}
