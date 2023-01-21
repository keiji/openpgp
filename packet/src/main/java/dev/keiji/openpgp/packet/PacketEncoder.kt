package dev.keiji.openpgp.packet

import java.io.OutputStream

object PacketEncoder {
    fun encode(isOld: Boolean, packetList: List<Packet>, outputStream: OutputStream) {
        packetList.forEach { packet ->
            packet.writeTo(isOld, outputStream)
        }
    }
}
