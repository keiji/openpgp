package dev.keiji.openpgp.packet.userattribute

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.userattribute.subpacket.Subpacket
import dev.keiji.openpgp.packet.userattribute.subpacket.SubpacketDecoder
import java.io.InputStream
import java.io.OutputStream

class PacketUserAttribute : Packet() {
    override val tagValue: Int = Tag.UserAttribute.value

    var subpacketList: List<Subpacket> = emptyList()

    override fun readContentFrom(inputStream: InputStream) {
        subpacketList = SubpacketDecoder.decode(inputStream.readBytes())
    }

    override fun writeContentTo(outputStream: OutputStream) {
        // Do nothing
    }

    override fun toDebugString(): String {
        return """
 * PacketUserAttribute
        """.trimIndent()
    }
}
