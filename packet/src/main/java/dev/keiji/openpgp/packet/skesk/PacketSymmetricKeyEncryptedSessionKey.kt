package dev.keiji.openpgp.packet.skesk

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag

abstract class PacketSymmetricKeyEncryptedSessionKey : Packet() {
    override val tagValue: Int = Tag.SymmetricKeyEncryptedSessionKey.value

    abstract val version: Int
}
