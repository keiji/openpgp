package dev.keiji.openpgp.packet

import java.io.OutputStream

object PacketEncoder {
    fun encode(isLegacyFormat: Boolean, packetList: List<Packet>, outputStream: OutputStream) {
        packetList.forEach { packet ->
            packet.writeTo(isLegacyFormat, outputStream)
        }
    }

    /**
     * Encodes each packet with the packet header format it carries
     * (the format it was decoded from, or the OpenPGP packet format
     * for newly built packets).
     */
    fun encode(packetList: List<Packet>, outputStream: OutputStream) {
        packetList.forEach { packet ->
            packet.writeTo(outputStream)
        }
    }
}
