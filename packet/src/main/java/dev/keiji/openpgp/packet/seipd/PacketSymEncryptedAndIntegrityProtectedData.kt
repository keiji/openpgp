package dev.keiji.openpgp.packet.seipd

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag
import java.io.InputStream
import java.io.OutputStream

abstract class PacketSymEncryptedAndIntegrityProtectedData : Packet() {
    override val tagValue: Int = Tag.SymEncryptedAndIntegrityProtectedData.value

    abstract val version: Int
}
