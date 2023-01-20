package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.packet.Tag

class PacketSecretSubkeyV4 : PacketSecretKeyV4() {
    override val tagValue: Int = Tag.SecretSubkey.value
}
