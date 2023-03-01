package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag

abstract class PacketSignature : Packet() {
    override val tagValue: Int = Tag.Signature.value

    abstract val version: Int

    abstract fun hash(contentBytes: ByteArray): ByteArray

    abstract fun hash(packetList: List<Packet>): ByteArray

    abstract fun getHashContentBytes(packetList: List<Packet>): ByteArray
}
