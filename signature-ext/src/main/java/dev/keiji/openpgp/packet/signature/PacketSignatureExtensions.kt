package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.publickey.PacketPublicKey

fun PacketSignature.verify(
    publicKeyPacket: PacketPublicKey,
    packetList: List<Packet>,
): Boolean {
    return when (this) {
        is PacketSignatureV4 -> {
            signature?.verify(
                publicKeyPacket,
                hashAlgorithm,
                getContentBytes(packetList)
            )
        }

        is PacketSignatureV5 -> {
            signature?.verify(
                publicKeyPacket,
                hashAlgorithm,
                getContentBytes(packetList)
            )
        }

        else -> throw throw UnsupportedAlgorithmException("")
    } ?: false

}
