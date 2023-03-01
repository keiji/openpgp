package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.signature.subpacket.Subpacket
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketDecoder
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder

class PacketSignatureV5 : PacketSignature() {
    companion object {
        const val VERSION: Int = 5
    }

    override val version: Int = VERSION

    var signatureType: SignatureType = SignatureType.BinaryDocument
    var publicKeyAlgorithm: OpenPgpAlgorithm = OpenPgpAlgorithm.ECDSA
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
        publicKeyAlgorithm = OpenPgpAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException("PublicKeyAlgorithm $publicKeyAlgorithmByte is not supported")

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

    override fun hash(contentBytes: ByteArray): ByteArray {
        return byteArrayOf()
    }

    override fun hash(packetList: List<Packet>): ByteArray {
        return byteArrayOf()
    }

    override fun getHashContentBytes(packetList: List<Packet>): ByteArray {
        return when (signatureType) {
            SignatureType.PrimaryKeyBinding -> {
                byteArrayOf()
            }

            else -> byteArrayOf()
        }
    }
}
