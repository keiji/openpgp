package dev.keiji.openpgp

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.PacketDecoder

class PgpMessage(
    private val pgpData: PgpData,
) {
    val packetList: List<Packet>
        get() {
            if (pgpData.blockList.isEmpty()) {
                throw InvalidPgpDataException("blockList is empty.")
            }

            val dataBytes = pgpData.blockList[0].data
            dataBytes ?: throw InvalidPgpDataException("data is null.")

            return PacketDecoder.decode(dataBytes)
        }
}
