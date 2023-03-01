package dev.keiji.openpgp.packet

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.onepass_signature.PacketOnePassSignatureV3
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.subpacket.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest

class PacketDecoderSignatureV4Test {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeSignatureTest() {
        val data =
            File(
                file.absolutePath,
                "hello_txt_signed_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
            )
                .readBytes()

        val contentData =
            File(
                file.absolutePath,
                "hello.txt"
            )
                .readBytes()

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        assertEquals(1, packetList.size)

        val packetCompressedData = packetList[0]
        assertEquals(Tag.CompressedData, packetCompressedData.tag)
        assertTrue(packetCompressedData is PacketCompressedData)
        if (packetCompressedData is PacketCompressedData) {
            assertEquals(
                CompressionAlgorithm.ZIP,
                packetCompressedData.compressionAlgorithm
            )

            val innerPacketList = PacketDecoder.decode(packetCompressedData.rawDataInputStream)
            assertEquals(3, innerPacketList.size)

            val packet0 = innerPacketList[0]
            assertTrue(packet0 is PacketOnePassSignatureV3)
            if (packet0 is PacketOnePassSignatureV3) {
                assertEquals("3E58DE6CC926B4AD", packet0.keyId.toHex())
                assertEquals(HashAlgorithm.SHA2_256, packet0.hashAlgorithm)
                assertEquals(OpenPgpAlgorithm.ECDSA, packet0.publicKeyAlgorithm)
                assertEquals(SignatureType.BinaryDocument, packet0.signatureType)
                assertEquals(0x01, packet0.flag)
            }

            val packet1 = innerPacketList[1]
            assertTrue(packet1 is PacketLiteralData)
            if (packet1 is PacketLiteralData) {
                assertEquals(1677421285, packet1.date)
                assertEquals("hello.txt", packet1.fileName)
                assertEquals(LiteralDataFormat.Binary, packet1.format)
                assertEquals("48656C6C6F20504750210A323032330A30320A3236", packet1.values.toHex())
                assertEquals(contentData.toHex(), packet1.values.toHex())
            }

            val packetSignature = innerPacketList[2]
            assertEquals(Tag.Signature, packetSignature.tag)
            assertTrue(packetSignature is PacketSignatureV4)
            if (packetSignature is PacketSignatureV4) {
                assertEquals(
                    SignatureType.BinaryDocument,
                    packetSignature.signatureType
                )
                assertEquals(OpenPgpAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
                assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

                val hashedSubpackets = packetSignature.hashedSubpacketList
                assertEquals(2, hashedSubpackets.size)

                val issuerFingerprintSubpacket = hashedSubpackets[0]
                assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
                if (issuerFingerprintSubpacket is IssuerFingerprint) {
                    assertEquals(4, issuerFingerprintSubpacket.version)
                    assertEquals(
                        "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                        issuerFingerprintSubpacket.fingerprint.toHex()
                    )
                }
                val signatureCreationTimeSubpacket = hashedSubpackets[1]
                assertEquals(
                    SubpacketType.SignatureCreationTime,
                    signatureCreationTimeSubpacket.getType()
                )
                if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                    assertEquals(1677421285, signatureCreationTimeSubpacket.value)
                }

                val subpackets = packetSignature.subpacketList
                assertEquals(1, subpackets.size)

                val issuerSubpacket = subpackets[0]
                assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
                if (issuerSubpacket is Issuer) {
                    assertEquals(
                        "3E58DE6CC926B4AD",
                        issuerSubpacket.keyId.toHex()
                    )
                }

                val hash2bytes = packetSignature.hash2bytes
                assertEquals(2, hash2bytes.size)
                assertEquals(
                    "76AC",
                    hash2bytes.toHex()
                )

                val signature = packetSignature.signature
                assertNotNull(signature)
                signature ?: return

                assertTrue(signature is SignatureEcdsa)
                if (signature is SignatureEcdsa) {
                    assertEquals(
                        "3E2310E598FAD2BAC5B81F33127CE5CCB8A55FB4ACFB21C8A75CD306CE8021DD",
                        signature.r?.toHex(),
                    )
                    assertEquals(
                        "18816880E3DAEE1452F2B882F2A38E3E81017249AC33626DC39703FF32764AC9",
                        signature.s?.toHex(),
                    )
                }

                // Verify signature
                val contentHash = packetSignature.hash(innerPacketList)
                assertEquals(0x76.toByte(), contentHash[0])
                assertEquals(0xAC.toByte(), contentHash[1])
                assertEquals("76ACF5ECAD6037C32F9D0085EDD468C4FBA48296395C05730F617045745B5D75", contentHash.toHex())
            }
        }
    }

    @Test
    fun decodeZipSignatureTest() {
        val data =
            File(
                file.absolutePath,
                "hello_txt_zip_signed_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
            )
                .readBytes()

        val contentData =
            File(
                file.absolutePath,
                "hello.txt.zip"
            )
                .readBytes()

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        assertEquals(1, packetList.size)

        val packetCompressedData = packetList[0]
        assertEquals(Tag.CompressedData, packetCompressedData.tag)
        assertTrue(packetCompressedData is PacketCompressedData)
        if (packetCompressedData is PacketCompressedData) {
            assertEquals(
                CompressionAlgorithm.ZIP,
                packetCompressedData.compressionAlgorithm
            )

            val innerPacketList = PacketDecoder.decode(packetCompressedData.rawDataInputStream)
            assertEquals(3, innerPacketList.size)

            val packet0 = innerPacketList[0]
            assertTrue(packet0 is PacketOnePassSignatureV3)
            if (packet0 is PacketOnePassSignatureV3) {
                assertEquals("3E58DE6CC926B4AD", packet0.keyId.toHex())
                assertEquals(HashAlgorithm.SHA2_256, packet0.hashAlgorithm)
                assertEquals(OpenPgpAlgorithm.ECDSA, packet0.publicKeyAlgorithm)
                assertEquals(SignatureType.BinaryDocument, packet0.signatureType)
                assertEquals(0x01, packet0.flag)
            }

            val packet1 = innerPacketList[1]
            assertTrue(packet1 is PacketLiteralData)
            if (packet1 is PacketLiteralData) {
                assertEquals(1677421294, packet1.date)
                assertEquals("hello.txt.zip", packet1.fileName)
                assertEquals(LiteralDataFormat.Binary, packet1.format)
                assertEquals(
                    contentData.toHex(),
                    packet1.values.toHex()
                )
            }

            val packetSignature = innerPacketList[2]
            assertEquals(Tag.Signature, packetSignature.tag)
            assertTrue(packetSignature is PacketSignatureV4)
            if (packetSignature is PacketSignatureV4) {
                assertEquals(
                    SignatureType.BinaryDocument,
                    packetSignature.signatureType
                )
                assertEquals(OpenPgpAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
                assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

                val hashedSubpackets = packetSignature.hashedSubpacketList
                assertEquals(2, hashedSubpackets.size)

                val issuerFingerprintSubpacket = hashedSubpackets[0]
                assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
                if (issuerFingerprintSubpacket is IssuerFingerprint) {
                    assertEquals(4, issuerFingerprintSubpacket.version)
                    assertEquals(
                        "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                        issuerFingerprintSubpacket.fingerprint.toHex()
                    )
                }
                val signatureCreationTimeSubpacket = hashedSubpackets[1]
                assertEquals(
                    SubpacketType.SignatureCreationTime,
                    signatureCreationTimeSubpacket.getType()
                )
                if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                    assertEquals(1677421294, signatureCreationTimeSubpacket.value)
                }

                val subpackets = packetSignature.subpacketList
                assertEquals(1, subpackets.size)

                val issuerSubpacket = subpackets[0]
                assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
                if (issuerSubpacket is Issuer) {
                    assertEquals(
                        "3E58DE6CC926B4AD",
                        issuerSubpacket.keyId.toHex()
                    )
                }

                val hash2bytes = packetSignature.hash2bytes
                assertEquals(2, hash2bytes.size)
                assertEquals(
                    "2744",
                    hash2bytes.toHex()
                )

                val signature = packetSignature.signature
                assertNotNull(signature)
                signature ?: return

                assertTrue(signature is SignatureEcdsa)
                if (signature is SignatureEcdsa) {
                    assertEquals(
                        "64B82721CC8D5C790B0B569F99368A14C5F74F31913961C296AC28EE5ED42E90",
                        signature.r?.toHex(),
                    )
                    assertEquals(
                        "99A10D066C6EE6E370835A792F32E68690BF39BB2DC4F0068EBE6B4EAC958CEC",
                        signature.s?.toHex(),
                    )
                }

                // Verify signature
                val contentHash = packetSignature.hash(innerPacketList)
                assertEquals(0x27.toByte(), contentHash[0])
                assertEquals(0x44.toByte(), contentHash[1])
                assertEquals("27442302DFCEE4A7D9EBD80B86BB9DBAEEA7B4BA88C76BA8378E0F304495371E", contentHash.toHex())
            }
        }
    }

    @Test
    fun decodeDetachedSignatureTest() {
        val data =
            File(
                file.absolutePath,
                "hello_txt_detatched_sign_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.sig"
            )
                .readBytes()

        val contentData =
            File(
                file.absolutePath,
                "hello.txt"
            )
                .readBytes()

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        assertEquals(1, packetList.size)

        val packetSignature = packetList[0]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.BinaryDocument,
                packetSignature.signatureType
            )
            assertEquals(OpenPgpAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

            val hashedSubpackets = packetSignature.hashedSubpacketList
            assertEquals(2, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                    issuerFingerprintSubpacket.fingerprint.toHex()
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1677592551, signatureCreationTimeSubpacket.value)
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "3E58DE6CC926B4AD",
                    issuerSubpacket.keyId.toHex()
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "38E6",
                hash2bytes.toHex()
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "2E167B14CD3EAC417D1AE216E108D5863C50672FD31163C8297E190D58E7F7B7",
                    signature.r?.toHex(),
                )
                assertEquals(
                    "107249C942DB2D3F2BCE71DC8349D22A75A2710C33C738884D0AEC14CA7C5FCF",
                    signature.s?.toHex(),
                )
            }

            // Verify signature
            val contentHash = packetSignature.hash(contentData)
            assertEquals(0x38.toByte(), contentHash[0])
            assertEquals(0xE6.toByte(), contentHash[1])
            assertEquals("38E618CF5D2FC787A095D71576CB7EE893879652AC17305347AE9F2A3CB22853", contentHash.toHex())
        }

    }
}
