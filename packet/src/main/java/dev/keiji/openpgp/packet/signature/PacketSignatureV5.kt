@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.UnsupportedSignatureTypeException
import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.PacketLiteralData
import dev.keiji.openpgp.packet.PacketUserId
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.subpacket.Subpacket
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketDecoder
import dev.keiji.openpgp.to2ByteArray
import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toInt
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder
import java.nio.charset.StandardCharsets
import javax.naming.OperationNotSupportedException

class PacketSignatureV5 : PacketSignature() {
    companion object {
        const val VERSION: Int = 5
    }

    override val version: Int = VERSION

    var signatureType: SignatureType = SignatureType.BinaryDocument
    var publicKeyAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
    var hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA2_512

    var hashedSubpacketList: List<Subpacket> = emptyList()
    var subpacketList: List<Subpacket> = emptyList()

    var hash2bytes: ByteArray = byteArrayOf()

    var salt: ByteArray = byteArrayOf()

    var signature: Signature? = null

    override fun readContentFrom(inputStream: InputStream) {
        val signatureTypeByte = inputStream.read()
        signatureType = SignatureType.findBy(signatureTypeByte)
            ?: throw UnsupportedSignatureTypeException("SignatureType $signatureTypeByte is not supported.")

        val publicKeyAlgorithmByte = inputStream.read()
        publicKeyAlgorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException(
                "PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported"
            )

        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
            ?: throw UnsupportedHashAlgorithmException("HashAlgorithm $publicKeyAlgorithmByte is not supported")

        val hashedSubpacketCountBytes = ByteArray(4).also {
            inputStream.read(it)
        }
        val hashedSubpacketCount = hashedSubpacketCountBytes.toInt()
        val hashedSubpackets = ByteArray(hashedSubpacketCount).also {
            inputStream.read(it)
        }

        hashedSubpacketList = SubpacketDecoder.decode(hashedSubpackets)

        val subpacketCountBytes = ByteArray(4).also {
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

        salt = ByteArray(16).also {
            inputStream.read(it)
        }

        signature = SignatureParser.parse(publicKeyAlgorithm, inputStream)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        // Do nothing
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * PacketSignatureV4\n" +
                    "   * Version: $version\n" +
                    "   * signatureType: ${signatureType.name}\n" +
                    "   * publicKeyAlgorithm: ${publicKeyAlgorithm.name}\n" +
                    "   * hashAlgorithm: ${hashAlgorithm.textName}\n" +
                    "   * hash2bytes: ${hash2bytes.toHex()}\n" +
                    ""
        )

        sb.append("hashedSubpacketList\n")
        hashedSubpacketList.forEach { subpacket ->
            sb.append(subpacket.toDebugString())
        }

        sb.append("subpacketList\n")
        subpacketList.forEach { subpacket ->
            sb.append(subpacket.toDebugString())
        }

        sb.append("   * signature:\n")
            .append(signature?.toDebugString())
            .append("\n")

        return sb.toString()
    }

    override fun getContentBytes(contentBytes: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()

        baos.write(contentBytes)
        baos.write(getTrailerBytes())

        return baos.toByteArray()
    }

    override fun getContentBytes(packetList: List<Packet>): ByteArray {
        val baos = ByteArrayOutputStream()

        baos.write(salt)

        when (signatureType) {
            SignatureType.GenericCertificationOfUserId,
            SignatureType.PersonaCertificationOfUserId,
            SignatureType.CasualCertificationOfUserId,
            SignatureType.PositiveCertificationOfUserId,
            -> {
                getCertificationOfUserIdBytes(packetList, baos)
            }

            SignatureType.BinaryDocument -> getBinaryDocument(packetList, baos)
            SignatureType.KeyRevocation -> getKeyRevocationBytes(packetList, baos)
            else -> {
                throw OperationNotSupportedException("SignatureType ${signatureType.name} is not supported.")
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

    private fun getKeyRevocationBytes(
        packetList: List<Packet>,
        outputStream: OutputStream
    ) {
        val keyPacket = packetList.first { it is PacketPublicKey } as PacketPublicKey
        val publicKeyPacket = keyPacket.convertToWxplicitPacketPublicKey()

        val publicKeyPacketBytes = ByteArrayOutputStream().let {
            publicKeyPacket.writeContentTo(it)
            it.toByteArray()
        }

        outputStream.write(0x99)
        outputStream.write(publicKeyPacketBytes.size.to2ByteArray())
        outputStream.write(publicKeyPacketBytes)
    }

    private fun getCertificationOfUserIdBytes(
        packetList: List<Packet>,
        outputStream: OutputStream
    ) {
        val keyPacket = packetList.first { it is PacketPublicKey } as PacketPublicKey

        val publicKeyPacket = keyPacket.convertToWxplicitPacketPublicKey()
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
