@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
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

/**
 * A version 6 Signature packet.
 *
 * The differences from a version 4 Signature packet are:
 *
 *  -  the hashed and unhashed subpacket length fields are 4 octets wide
 *     instead of 2 octets,
 *
 *  -  a variable-length salt (a 1-octet salt size followed by the salt)
 *     follows the left 16 bits of the signed hash value, and
 *
 *  -  the salt is fed into the hash context before any other data.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3
 */
class PacketSignatureV6 : PacketSignature() {
    companion object {
        const val VERSION: Int = 6
    }

    override val version: Int = VERSION

    var signatureType: SignatureType = SignatureType.BinaryDocument
    var publicKeyAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ED25519
    var hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA2_512

    var hashedSubpacketList: List<Subpacket> = emptyList()
    var subpacketList: List<Subpacket> = emptyList()

    var hash2bytes: ByteArray = byteArrayOf()

    var salt: ByteArray = byteArrayOf()
        set(value) {
            require(value.size == expectedSaltSize) {
                "salt length must be ${expectedSaltSize} " +
                        "but ${value.size} for ${hashAlgorithm.textName}"
            }
            field = value
        }

    var signature: Signature? = null

    private val expectedSaltSize: Int
        get() {
            val saltSize = hashAlgorithm.v6SaltSize
                ?: throw UnsupportedHashAlgorithmException(
                    "HashAlgorithm ${hashAlgorithm.textName} can not be used " +
                            "by a version 6 signature."
                )
            return saltSize
        }

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
            ?: throw UnsupportedHashAlgorithmException(
                "HashAlgorithm $hashAlgorithmByte is not supported"
            )

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

        val saltSize = inputStream.read()
        if (saltSize != expectedSaltSize) {
            throw UnsupportedSignatureTypeException(
                "Salt size $saltSize does not match " +
                        "the salt size ${expectedSaltSize} of ${hashAlgorithm.textName}."
            )
        }
        salt = ByteArray(saltSize).also {
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
        outputStream.write(hashedSubpacketBytes.size.toByteArray())
        outputStream.write(hashedSubpacketBytes)

        val subpacketBytes = ByteArrayOutputStream().let { baos ->
            subpacketList.forEach {
                it.writeTo(baos)
            }
            baos.toByteArray()
        }
        outputStream.write(subpacketBytes.size.toByteArray())
        outputStream.write(subpacketBytes)

        outputStream.write(hash2bytes)

        val saltSnapshot = if (salt.isNotEmpty()) {
            salt
        } else {
            ByteArray(expectedSaltSize)
        }
        outputStream.write(saltSnapshot.size)
        outputStream.write(saltSnapshot)

        signature?.writeTo(outputStream)
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * PacketSignatureV6\n" +
                    "   * Version: $version\n" +
                    "   * signatureType: ${signatureType.name}\n" +
                    "   * publicKeyAlgorithm: ${publicKeyAlgorithm.name}\n" +
                    "   * hashAlgorithm: ${hashAlgorithm.textName}\n" +
                    "   * hash2bytes: ${hash2bytes.toHex()}\n" +
                    "   * salt: ${salt.toHex()}\n" +
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

        baos.write(salt)
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
            -> getCertificationOfUserIdBytes(packetList, baos)

            SignatureType.CertificationRevocation -> getCertificationOfUserIdBytes(packetList, baos)

            SignatureType.BinaryDocument -> getDocumentBytes(packetList, baos, canonicalize = false)
            SignatureType.CanonicalTextDocument -> getDocumentBytes(packetList, baos, canonicalize = true)

            SignatureType.SignatureDirectlyOnKey -> getKeyHashPrefixes(packetList, baos, includeSubkey = false)
            SignatureType.KeyRevocation -> getKeyHashPrefixes(packetList, baos, includeSubkey = false)
            SignatureType.SubKeyBinding -> getKeyHashPrefixes(packetList, baos, includeSubkey = true)
            SignatureType.SubKeyRevocation -> getKeyHashPrefixes(packetList, baos, includeSubkey = true)

            else -> {
                throw OperationNotSupportedException(
                    "SignatureType ${signatureType.name} is not supported."
                )
            }
        }

        baos.write(getTrailerBytes())

        return baos.toByteArray()
    }

    private fun getDocumentBytes(
        packetList: List<Packet>,
        outputStream: OutputStream,
        canonicalize: Boolean,
    ) {
        val keyPacket = packetList.first { it is PacketLiteralData } as PacketLiteralData

        // For text document signatures, the implementation MUST first
        // canonicalize the document by converting line endings to
        // <CR><LF> and encoding it in UTF-8. The resulting byte stream
        // is hashed. Binary document signatures hash the document data
        // directly.
        if (canonicalize) {
            val canonicalized = PgpData.canonicalize(
                String(keyPacket.values, charset = StandardCharsets.UTF_8)
            )
            outputStream.write(canonicalized)
        } else {
            outputStream.write(keyPacket.values)
        }
    }

    private fun getKeyHashPrefixes(
        packetList: List<Packet>,
        outputStream: OutputStream,
        includeSubkey: Boolean,
    ) {
        val keyPacketList = packetList.filterIsInstance<PacketPublicKey>()
        val primaryKeyPacket = keyPacketList.first()

        writeKeyHashPrefix(outputStream, primaryKeyPacket)

        if (includeSubkey) {
            val subkeyPacket = keyPacketList.last()
            writeKeyHashPrefix(outputStream, subkeyPacket)
        }
    }

    private fun writeKeyHashPrefix(
        outputStream: OutputStream,
        keyPacket: PacketPublicKey,
    ) {
        val publicKeyPacket = keyPacket.convertToWxplicitPacketPublicKey()

        val publicKeyPacketBytes = ByteArrayOutputStream().let {
            publicKeyPacket.writeContentTo(it)
            it.toByteArray()
        }

        when (publicKeyPacket.version) {
            VERSION -> {
                // 0x9B, followed by the four-octet packet length,
                // followed by the body of the key packet.
                outputStream.write(0x9B)
                outputStream.write(publicKeyPacketBytes.size.toByteArray())
            }

            PacketSignatureV4.VERSION -> {
                // 0x99, followed by the two-octet packet length,
                // followed by the body of the key packet.
                outputStream.write(0x99)
                outputStream.write(publicKeyPacketBytes.size.to2ByteArray())
            }

            else -> throw UnsupportedSignatureTypeException(
                "Key version ${publicKeyPacket.version} is not supported."
            )
        }

        outputStream.write(publicKeyPacketBytes)
    }

    private fun getCertificationOfUserIdBytes(
        packetList: List<Packet>,
        outputStream: OutputStream,
    ) {
        val keyPacket = packetList.first { it is PacketPublicKey } as PacketPublicKey

        val publicKeyPacket = keyPacket.convertToWxplicitPacketPublicKey()
        val userIdPacket = packetList.first { it is PacketUserId } as PacketUserId

        writeKeyHashPrefix(outputStream, publicKeyPacket)

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
            baos.write(hashedSubpacketBody.size.toByteArray())
            baos.write(hashedSubpacketBody)

            val size = baos.size()

            baos.write(version)
            baos.write(0xFF)
            baos.write(size.toByteArray())
            baos.toByteArray()
        }
    }
}
