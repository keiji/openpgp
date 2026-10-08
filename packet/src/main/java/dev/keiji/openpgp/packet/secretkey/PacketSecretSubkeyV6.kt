package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.packet.Tag

class PacketSecretSubkeyV6 : PacketSecretKeyV6() {
    override val tagValue: Int = Tag.SecretSubkey.value
}
