package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV5

class PacketPublicSubkeyV5 : PacketPublicKeyV5() {
    override val tagValue: Int = Tag.PublicSubkey.value
}
