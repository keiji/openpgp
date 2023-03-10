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
import java.nio.charset.StandardCharsets

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

    fun isAsciiArmoredForm(encoded: String): Boolean {
        val lines = encoded.trim().lines()
        if (lines.size < 4) {
            return false
        }

        if (!lines.first().startsWith("-----") || !lines.first().endsWith("-----")) {
            return false
        }

        if (!lines.last().startsWith("-----") || !lines.last().endsWith("-----")) {
            return false
        }

        // Seek first blank line.
        var blankLineNumber = -1
        for (index in lines.indices) {
            if (lines[index].isNotBlank()) {
                continue
            }
            blankLineNumber = index
            break
        }

        if (blankLineNumber == -1) {
            return false
        }

        return true
    }

    @Throws(ObsoletePacketDetectedException::class)
    fun decode(
        byteArray: ByteArray,
    ): List<Packet> {
        val dataAsString = String(byteArray, charset = StandardCharsets.UTF_8)
        val inputStream = if (isAsciiArmoredForm(dataAsString)) {
            val (body, parity) = split(dataAsString)
            val decoded = Radix64.decode(body)
            ByteArrayInputStream(decoded)
        } else {
            ByteArrayInputStream(byteArray)
        }

        return decode(inputStream)
    }

    @Throws(ObsoletePacketDetectedException::class)
    fun decode(
        encoded: String,
    ): List<Packet> {
        val (body, parity) = split(encoded)
        val decoded = Radix64.decode(body)
        val inputStream = ByteArrayInputStream(decoded)

        return decode(inputStream)
    }

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
