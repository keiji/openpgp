package dev.keiji.openpgp

import dev.keiji.openpgp.packet.PacketDecoder
import dev.keiji.openpgp.packet.signature.PacketSignature
import java.nio.charset.StandardCharsets

class PgpCleartextSignature(
    private val pgpData: PgpData,
) {
    val cleartext: String
        get() {
            if (pgpData.blockList.isEmpty()) {
                throw CleartextNotFoundException("blockList is empty.")
            }

            val cleartextBlock = pgpData.blockList[0]
            if (cleartextBlock.type != PgpData.BlockType.PGP_SIGNED_MESSAGE) {
                throw CleartextNotFoundException("PgpData is not contains PGP SIGNED MESSAGE.")
            }

            val textBytes = cleartextBlock.data
            textBytes ?: throw CleartextNotFoundException("Cleartext is null.")

            return String(textBytes, charset = StandardCharsets.UTF_8)
        }

    val signaturePacket: PacketSignature
        get() {
            if (pgpData.blockList.isEmpty()) {
                throw CleartextNotFoundException("blockList is empty.")
            }

            val cleartextBlock = pgpData.blockList[0]
            if (cleartextBlock.type != PgpData.BlockType.PGP_SIGNED_MESSAGE) {
                throw CleartextNotFoundException("PgpData is not contains PGP SIGNED MESSAGE.")
            }

            val cleartextSubBlockList = cleartextBlock.blockList
            if (cleartextSubBlockList.isEmpty()) {
                throw PgpSignatureNotFoundException("Cleartext subblock list is empty.")
            }

            val pgpSignatureBlock = cleartextSubBlockList[0]
            if (pgpSignatureBlock.type == PgpData.BlockType.PGP_SIGNATURE) {
                throw PgpSignatureNotFoundException("PgpData is not contains PGP SIGNATURE.")
            }

            val packetBytes = pgpSignatureBlock.data
            packetBytes ?: throw PgpSignatureNotFoundException("PGP SIGNATURE is null.")

            val packetList = PacketDecoder.decode(packetBytes)
            val packet = packetList.firstOrNull { it is PacketSignature } as PacketSignature?
            packet ?: throw PgpSignatureNotFoundException("Signature packet not found.")

            return packet
        }
}
