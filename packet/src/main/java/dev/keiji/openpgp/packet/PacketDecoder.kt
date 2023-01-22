package dev.keiji.openpgp.packet

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

    fun decode(
        encoded: String,
    ): List<Packet> {
        val packetList = mutableListOf<Packet>()

        decode(encoded, object : Callback {
            override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                val tag = Tag.findBy(header.tagValue)
                val bais = ByteArrayInputStream(byteArray)

                val packet = when (tag) {
                    Tag.PublicKey -> PacketPublicKeyParser.parse(bais)
                    Tag.PublicSubkey -> PacketPublicSubkeyParser.parse(bais)
                    Tag.SecretKey -> PacketSecretKeyParser.parse(bais)
                    Tag.SecretSubkey -> PacketSecretSubkeyParser.parse(bais)
                    Tag.UserId -> PacketUserId().also { it.readFrom(bais) }
                    Tag.UserAttribute -> PacketUserAttribute().also { it.readFrom(bais) }
                    Tag.Signature -> PacketSignatureParser.parse(bais)
                    Tag.SymmetricKeyEncryptedSessionKey -> {
                        PacketSymmetricKeyEncryptedSessionKeyParser.parse(bais)
                    }

                    Tag.SymEncryptedAndIntegrityProtectedData -> {
                        PacketSymEncryptedAndIntegrityProtectedDataParser.parse(bais)
                    }

                    else -> PacketUnknown(header.tagValue).also { it.readFrom(bais) }
                }
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

    fun decode(encoded: String, callback: Callback) {
        val (body, parity) = split(encoded)
        val decoded = Radix64.decode(body)
        val inputStream = ByteArrayInputStream(decoded)

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
}
