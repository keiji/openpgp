package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.packet.Tag

class PacketPublicSubkeyV6 : PacketPublicKeyV6() {
    override val tagValue: Int = Tag.PublicSubkey.value
}
