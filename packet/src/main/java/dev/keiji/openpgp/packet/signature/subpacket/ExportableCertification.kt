package dev.keiji.openpgp.packet.signature.subpacket

import java.io.InputStream
import java.io.OutputStream

private const val EXPORTABLE = 1

class ExportableCertification : Subpacket() {
    override val typeValue: Int = SubpacketType.ExportableCertification.value

    var value: Boolean = false

    override fun readFrom(inputStream: InputStream) {
        value = inputStream.read() == EXPORTABLE
    }

    override fun writeContentTo(outputStream: OutputStream) {
        if (value) {
            outputStream.write(EXPORTABLE)
        } else {
            outputStream.write(0)
        }
    }

    override fun toDebugString(): String {
        return " * ExportableCertification\n" +
                "   * value: $value\n" +
                ""
    }
}
