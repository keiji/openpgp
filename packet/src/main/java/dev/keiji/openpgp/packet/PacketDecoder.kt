package dev.keiji.openpgp.packet

import dev.keiji.openpgp.ObsoletePacketDetectedException
import dev.keiji.openpgp.packet.onepass_signature.PacketOnePassSignatureParser
import dev.keiji.openpgp.packet.skesk.PacketSymmetricKeyEncryptedSessionKeyParser
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyParser
import dev.keiji.openpgp.packet.publickey.PacketPublicSubkeyParser
import dev.keiji.openpgp.packet.secretkey.PacketSecretKeyParser
import dev.keiji.openpgp.packet.secretkey.PacketSecretSubkeyParser
import dev.keiji.openpgp.packet.seipd.PacketSymEncryptedAndIntegrityProtectedDataParser
import dev.keiji.openpgp.packet.signature.PacketSignatureParser
import dev.keiji.openpgp.packet.userattribute.PacketUserAttribute
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.math.BigInteger

object PacketDecoder {
    interface Callback {
        fun onPacketDetected(header: PacketHeader, byteArray: ByteArray)
        fun onPacketDetected(header: PacketHeader, inputStream: InputStream) {}
    }

    @Throws(ObsoletePacketDetectedException::class)
    fun decode(
        byteArray: ByteArray,
        callback: Callback,
    ) = decode(
        ByteArrayInputStream(byteArray),
        callback,
    )

    fun decode(inputStream: InputStream, callback: Callback) {
        while (inputStream.available() > 0) {
            val header = PacketHeader().also {
                it.readFrom(inputStream)
            }

            if (
                header.length > BigInteger.valueOf(Integer.MAX_VALUE.toLong()) ||
                header.length == PacketHeader.LENGTH_INDETERMINATE
            ) {
                callback.onPacketDetected(header, inputStream)
                continue
            }

            val data = ByteArray(header.length.toInt()).also {
                inputStream.read(it)
            }
            callback.onPacketDetected(header, data)
        }
    }

    @Throws(ObsoletePacketDetectedException::class)
    fun decode(
        byteArray: ByteArray,
    ): List<Packet> = decode(ByteArrayInputStream(byteArray))

    @Throws(ObsoletePacketDetectedException::class)
    fun decode(
        inputStream: InputStream,
    ): List<Packet> {
        val packetList = mutableListOf<Packet>()

        decode(inputStream, object : Callback {
            override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                val bais = ByteArrayInputStream(byteArray)
                onPacketDetected(header, bais)
            }

            override fun onPacketDetected(header: PacketHeader, inputStream: InputStream) {
                super.onPacketDetected(header, inputStream)

                val tag = Tag.findBy(header.tagValue)

                val packet = when (tag) {
                    Tag.PublicKey -> PacketPublicKeyParser.parse(inputStream)
                    Tag.PublicSubkey -> PacketPublicSubkeyParser.parse(inputStream)
                    Tag.SecretKey -> PacketSecretKeyParser.parse(inputStream)
                    Tag.SecretSubkey -> PacketSecretSubkeyParser.parse(inputStream)
                    Tag.CompressedData -> PacketCompressedData().also { it.readContentFrom(inputStream) }

                    /*
                     * This packet is obsolete.
                     * An implementation MUST NOT create this packet.
                     * An implementation MAY process such a packet but it MUST return a clear diagnostic that a non-integrity protected packet has been processed.
                     * The implementation SHOULD also return an error in this case and stop processing.
                     */
                    Tag.SymmetricallyEncryptedDataPacket -> {
                        throw ObsoletePacketDetectedException("Symmetrically Encrypted Data Packet is obsolete.")
                        // PacketSymmetricallyEncryptedData().also { it.readContentFrom(bais) }
                    }

                    Tag.UserId -> PacketUserId().also { it.readContentFrom(inputStream) }
                    Tag.UserAttribute -> PacketUserAttribute().also { it.readContentFrom(inputStream) }
                    Tag.Signature -> PacketSignatureParser.parse(inputStream)
                    Tag.OnePassSignature -> PacketOnePassSignatureParser.parse(inputStream)
                    Tag.SymmetricKeyEncryptedSessionKey -> {
                        PacketSymmetricKeyEncryptedSessionKeyParser.parse(inputStream)
                    }

                    Tag.Marker -> PacketMarker().also { it.readContentFrom(inputStream) }
                    Tag.LiteralData -> PacketLiteralData().also { it.readContentFrom(inputStream) }

                    /*
                     * Trust packet is used only within keyrings and is not normally exported.
                     * Trust packets SHOULD NOT be emitted to output streams that are transferred to other users,
                     * and they SHOULD be ignored on any input other than local keyring file.
                     */
                    Tag.Trust -> null // PacketTrust().also { it.readContentFrom(bais) }

                    Tag.SymEncryptedAndIntegrityProtectedData -> {
                        PacketSymEncryptedAndIntegrityProtectedDataParser.parse(inputStream)
                    }

                    Tag.Padding -> PacketPadding().also { it.readContentFrom(inputStream) }

                    else -> PacketUnknown(header.tagValue).also { it.readContentFrom(inputStream) }
                }

                packet ?: return

                packetList.add(packet)
            }
        })

        return packetList
    }
}
