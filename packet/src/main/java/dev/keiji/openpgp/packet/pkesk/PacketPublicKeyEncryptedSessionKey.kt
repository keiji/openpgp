package dev.keiji.openpgp.packet.pkesk

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag

abstract class PacketPublicKeyEncryptedSessionKey : Packet() {
    override val tagValue: Int = Tag.PublicKeyEncryptedSessionKey.value

    abstract val version: Int
}
