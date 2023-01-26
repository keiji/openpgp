package dev.keiji.openpgp.packet

import dev.keiji.openpgp.ObsoletePacketDetectedException
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
    private fun isParityLine(line: String) = line[0] == '=' && line[1] != '='

    interface Callback {
        fun onPacketDetected(header: PacketHeader, byteArray: ByteArray)
        fun onPacketDetected(header: PacketHeader, inputStream: InputStream) {}
    }

    fun decode(encoded: String, callback: Callback) {
        val (body, parity) = split(encoded)
        val decoded = Radix64.decode(body)
        val inputStream = ByteArrayInputStream(decoded)

        decode(inputStream, callback)
    }

    fun decode(
        encoded: String,
    ): List<Packet> {
        val (body, parity) = split(encoded)
        val decoded = Radix64.decode(body)
        val inputStream = ByteArrayInputStream(decoded)

        return decode(inputStream)
    }

    fun decode(inputStream: InputStream, callback: Callback) {
        while (inputStream.available() > 0) {
            val header = PacketHeader().also {
                it.readFrom(inputStream)
            }

            if (header.length > BigInteger.valueOf(Integer.MAX_VALUE.toLong())) {
                callback.onPacketDetected(header, inputStream)
                continue
            }

            val data = ByteArray(header.length.toInt()).also {
                inputStream.read(it)
            }
            callback.onPacketDetected(header, data)
        }
    }

    fun decode(
        inputStream: InputStream,
    ): List<Packet> {
        val packetList = mutableListOf<Packet>()

        decode(inputStream, object : Callback {
            override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                val tag = Tag.findBy(header.tagValue)
                val bais = ByteArrayInputStream(byteArray)

                val packet = when (tag) {
                    Tag.PublicKey -> PacketPublicKeyParser.parse(bais)
                    Tag.PublicSubkey -> PacketPublicSubkeyParser.parse(bais)
                    Tag.SecretKey -> PacketSecretKeyParser.parse(bais)
                    Tag.SecretSubkey -> PacketSecretSubkeyParser.parse(bais)
                    Tag.CompressedData -> PacketCompressedData().also { it.readContentFrom(bais) }

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

                    Tag.UserId -> PacketUserId().also { it.readContentFrom(bais) }
                    Tag.UserAttribute -> PacketUserAttribute().also { it.readContentFrom(bais) }
                    Tag.Signature -> PacketSignatureParser.parse(bais)
                    Tag.SymmetricKeyEncryptedSessionKey -> {
                        PacketSymmetricKeyEncryptedSessionKeyParser.parse(bais)
                    }

                    Tag.Marker -> PacketMarker().also { it.readContentFrom(bais) }
                    Tag.LiteralData -> PacketLiteralData().also { it.readContentFrom(bais) }

                    /*
                     * Trust packet is used only within keyrings and is not normally exported.
                     * Trust packets SHOULD NOT be emitted to output streams that are transferred to other users,
                     * and they SHOULD be ignored on any input other than local keyring file.
                     */
                    Tag.Trust -> null // PacketTrust().also { it.readContentFrom(bais) }

                    Tag.SymEncryptedAndIntegrityProtectedData -> {
                        PacketSymEncryptedAndIntegrityProtectedDataParser.parse(bais)
                    }

                    Tag.Padding -> PacketPadding().also { it.readContentFrom(bais) }

                    else -> PacketUnknown(header.tagValue).also { it.readContentFrom(bais) }
                }

                packet ?: return

                packetList.add(packet)
            }
        })

        return packetList
    }

    fun split(encoded: String): Pair<String, String?> {
        val radix64Encoded = encoded
            .split("\n")
            .filter { !it.startsWith("-----") }
            .filter { !it.contains(":") }
            .filter { it.isNotBlank() }

        val lastLine = radix64Encoded.last()
        val parity = if (isParityLine(lastLine)) lastLine else null

        val body = if (parity != null) {
            radix64Encoded
                .subList(0, radix64Encoded.size - 1)
                .joinToString("")
        } else {
            radix64Encoded.joinToString("")
        }

        return Pair(body, parity)
    }
}
