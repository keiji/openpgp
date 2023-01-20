package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.packet.Tag

class PacketSecretSubkeyV5 : PacketSecretKeyV5() {
    override val tagValue: Int = Tag.SecretSubkey.value
}
