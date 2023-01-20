package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag

abstract class PacketSignature : Packet() {
    override val tagValue: Int = Tag.Signature.value

    abstract val version: Int
}
