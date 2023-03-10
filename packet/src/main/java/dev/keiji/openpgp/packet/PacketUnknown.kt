package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream

class PacketUnknown(override val tagValue: Int) : Packet() {

    var values: ByteArray = byteArrayOf()

    override fun readContentFrom(inputStream: InputStream) {
        values = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(values)
    }

    override fun toDebugString(): String {
        return " * PacketUnknown\n" +
                "   * ${values.toHex("")}\n"
    }
}
