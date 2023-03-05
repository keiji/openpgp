package dev.keiji.openpgp.packet

import java.io.OutputStream

object PacketEncoder {
    fun encode(isLegacyFormat: Boolean, packetList: List<Packet>, outputStream: OutputStream) {
        packetList.forEach { packet ->
            packet.writeTo(isLegacyFormat, outputStream)
        }
    }
}
