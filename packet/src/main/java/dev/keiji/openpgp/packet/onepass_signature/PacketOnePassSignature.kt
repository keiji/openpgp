package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag

abstract class PacketOnePassSignature : Packet() {
    override val tagValue: Int = Tag.OnePassSignature.value

    abstract val version: Int
}
