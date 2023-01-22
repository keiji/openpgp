package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.signature.subpacket.Subpacket
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketDecoder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder

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

    override fun readFrom(inputStream: InputStream) {
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

        hashedSubpacketList.forEach { subpacket ->
            sb.append(subpacket.toString())
        }

        subpacketList.forEach { subpacket ->
            sb.append(subpacket.toString())
        }

        sb.append("   * signature:\n")
            .append(signature?.toString())

        return sb.toString()
    }
}
