package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.PacketLiteralData
import dev.keiji.openpgp.packet.PacketUserId
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyParser
import dev.keiji.openpgp.packet.signature.subpacket.Subpacket
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketDecoder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

open class PacketSignatureV4 : PacketSignature() {
    companion object {
        const val VERSION: Int = 4
    }

    override val version: Int = VERSION

    var signatureType: SignatureType = SignatureType.BinaryDocument
    var publicKeyAlgorithm: OpenPgpAlgorithm = OpenPgpAlgorithm.ECDSA
    var hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA2_512

    var hashedSubpacketList: List<Subpacket> = emptyList()
    var subpacketList: List<Subpacket> = emptyList()

    var hash2bytes: ByteArray = byteArrayOf()

    var signature: Signature? = null

    override fun readContentFrom(inputStream: InputStream) {
        val signatureTypeByte = inputStream.read()
        signatureType = SignatureType.findBy(signatureTypeByte)
            ?: throw UnsupportedSignatureTypeException("SignatureType $signatureTypeByte is not supported.")

        val publicKeyAlgorithmByte = inputStream.read()
        publicKeyAlgorithm = OpenPgpAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException("PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported")

        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
            ?: throw UnsupportedHashAlgorithmException("HashAlgorithm $publicKeyAlgorithmByte is not supported")

        val hashedSubpacketCountBytes = ByteArray(2).also {
            inputStream.read(it)
        }
        val hashedSubpacketCount = hashedSubpacketCountBytes.toInt()
        val hashedSubpackets = ByteArray(hashedSubpacketCount).also {
            inputStream.read(it)
        }

        hashedSubpacketList = SubpacketDecoder.decode(hashedSubpackets)

        val subpacketCountBytes = ByteArray(2).also {
            inputStream.read(it)
        }
        val subpacketCount = subpacketCountBytes.toInt()
        val subpackets = ByteArray(subpacketCount).also {
            inputStream.read(it)
        }

        subpacketList = SubpacketDecoder.decode(subpackets)

        hash2bytes = ByteArray(2).also {
            inputStream.read(it)
        }

        signature = SignatureParser.parse(publicKeyAlgorithm, inputStream)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(version)
        outputStream.write(signatureType.value)
        outputStream.write(publicKeyAlgorithm.id)
        outputStream.write(hashAlgorithm.id)

        val hashedSubpacketBytes = ByteArrayOutputStream().let { baos ->
            hashedSubpacketList.forEach {
                it.writeTo(baos)
            }
            baos.toByteArray()
        }
        val hashedSubpacketCount = hashedSubpacketBytes.size
        outputStream.write(hashedSubpacketCount.to2ByteArray())
        outputStream.write(hashedSubpacketBytes)

        val subpacketBytes = ByteArrayOutputStream().let { baos ->
            subpacketList.forEach {
                it.writeTo(baos)
            }
            baos.toByteArray()
        }
        outputStream.write(subpacketBytes.size.to2ByteArray())
        outputStream.write(subpacketBytes)

        outputStream.write(hash2bytes)

        signature?.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * PacketSignatureV4\n" +
                    "   * Version: $version\n" +
                    "   * signatureType: ${signatureType.name}\n" +
                    "   * publicKeyAlgorithm: ${publicKeyAlgorithm.name}\n" +
                    "   * hashAlgorithm: ${hashAlgorithm.name}\n" +
                    "   * hash2bytes: ${hash2bytes.toHex()}\n" +
                    ""
        )

        sb.append("   * hashedSubpacketList\n")
        hashedSubpacketList.forEach { subpacket ->
            sb.append(subpacket.toString())
        }

        sb.append("   * subpacketList\n")
        subpacketList.forEach { subpacket ->
            sb.append(subpacket.toString())
        }

        sb.append("   * signature:\n")
            .append(signature?.toString())

        return sb.toString()
    }

    override fun hash(packetList: List<Packet>): ByteArray {
        val contentBytes = getHashContentBytes(packetList)
        val md = MessageDigest.getInstance(hashAlgorithm.textName)
        return md.digest(contentBytes)
    }

    override fun getHashContentBytes(packetList: List<Packet>): ByteArray {
        val baos = ByteArrayOutputStream()

        when (signatureType) {
            SignatureType.GenericCertificationOfUserId,
            SignatureType.PersonaCertificationOfUserId,
            SignatureType.CasualCertificationOfUserId,
            SignatureType.PositiveCertificationOfUserId,
            -> {
                getCertificationOfUserIdBytes(packetList, baos)
            }

            SignatureType.BinaryDocument -> getBinaryDocument(packetList, baos)
            else -> {
                // Do Nothing.
            }
        }

        baos.write(getTrailerBytes())

        return baos.toByteArray()
    }

    private fun getBinaryDocument(
        packetList: List<Packet>,
        outputStream: OutputStream
    ) {
        val keyPacket = packetList.first { it is PacketLiteralData } as PacketLiteralData
        outputStream.write(keyPacket.values)
    }

    private fun getCertificationOfUserIdBytes(
        packetList: List<Packet>,
        outputStream: OutputStream
    ) {
        val keyPacket = packetList.first { it is PacketPublicKey } as PacketPublicKey

        val publicKeyPacket = convertToPacketPublicKey(keyPacket)
        val userIdPacket = packetList.first { it is PacketUserId } as PacketUserId

        val publicKeyPacketBytes = ByteArrayOutputStream().let {
            publicKeyPacket.writeContentTo(it)
            it.toByteArray()
        }

        outputStream.write(0x99)
        outputStream.write(publicKeyPacketBytes.size.to2ByteArray())
        outputStream.write(publicKeyPacketBytes)

        val idBytes = userIdPacket.userId.toByteArray(charset = StandardCharsets.UTF_8)
        outputStream.write(0xB4)
        outputStream.write(idBytes.size.toByteArray())
        outputStream.write(idBytes)
    }

    private fun getTrailerBytes(): ByteArray {
        val hashedSubpacketBody = ByteArrayOutputStream().let { baos ->
            this.hashedSubpacketList.forEach {
                it.writeTo(baos)
            }
            baos.toByteArray()
        }
        return ByteArrayOutputStream().let { baos ->
            baos.write(version)
            baos.write(signatureType.value)
            baos.write(publicKeyAlgorithm.id)
            baos.write(hashAlgorithm.id)
            baos.write(hashedSubpacketBody.size.to2ByteArray())
            baos.write(hashedSubpacketBody)

            val size = baos.size()

            baos.write(version)
            baos.write(0xFF)
            baos.write(size.toByteArray())
            baos.toByteArray()
        }
    }
}

/**
 * Convert explicitly from PacketPublicKey or PacketSecretKey to PacketPublicKey object.
 */
private fun convertToPacketPublicKey(keyPacket: PacketPublicKey): PacketPublicKey {
    return ByteArrayOutputStream().let {
        keyPacket.writeContentTo(it)
        val keyPacketBytes = it.toByteArray()
        PacketPublicKeyParser.parse(ByteArrayInputStream(keyPacketBytes))
    }
}
