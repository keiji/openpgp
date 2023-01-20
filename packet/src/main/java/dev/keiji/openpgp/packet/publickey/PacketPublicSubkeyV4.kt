package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4

class PacketPublicSubkeyV4 : PacketPublicKeyV4() {
    override val tagValue: Int = Tag.PublicSubkey.value
}
