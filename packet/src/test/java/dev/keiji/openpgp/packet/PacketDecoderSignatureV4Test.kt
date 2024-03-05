@file:Suppress(
    "LongMethod",
    "MaxLineLength",
)

package dev.keiji.openpgp.packet

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.onepass_signature.PacketOnePassSignatureV3
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.SignatureRsa
import dev.keiji.openpgp.packet.signature.subpacket.Issuer
import dev.keiji.openpgp.packet.signature.subpacket.IssuerFingerprint
import dev.keiji.openpgp.packet.signature.subpacket.SignatureCreationTime
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest

class PacketDecoderSignatureV4Test {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeClearTextSignatureTest() {
        val signatureFile =
            File(
                file.absolutePath,
                "hello_gpg_txt_clearsigned_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
            )

        val pgpData = PgpData.load(signatureFile)

        val clearText = pgpData.blockList[0].data
        assertNotNull(clearText)
        clearText ?: return

        val signatureData = pgpData.blockList[0].blockList[0].data
        assertNotNull(signatureData)
        signatureData ?: return

        val packetList = PacketDecoder.decode(signatureData)
        assertEquals(1, packetList.size)

        val packetSignature = packetList[0]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.CanonicalTextDocument,
                packetSignature.signatureType
            )
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
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
                assertEquals(1679053235, signatureCreationTimeSubpacket.value)
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
                "D111",
                hash2bytes.toHex()
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "23E8B5844A296156509D62D9B716D35185B13814046260272B314F2533F5D7A8",
                    signature.r?.toHex(),
                )
                assertEquals(
                    "77F15B68E51FFEC19A32E8260DC5B2378E71E726DC4E1E9C79C7B22B536B9A4A",
                    signature.s?.toHex(),
                )
            }

            // Verify signature
            val contentBytes = packetSignature.getContentBytes(clearText)
            val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                it.update(contentBytes)
                it.digest()
            }
            assertEquals(0xD1.toByte(), contentHashBytes[0])
            assertEquals(0x11.toByte(), contentHashBytes[1])
            assertEquals(
                "D111DDC4FCC5328AEE1E5EA366B6787DD2F2CAD058B3B6DA9D2BEA45A22FB2D3",
                contentHashBytes.toHex()
            )
        }
    }

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
                assertEquals(PublicKeyAlgorithm.ECDSA, packet0.publicKeyAlgorithm)
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
                assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
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
                val contentBytes = packetSignature.getContentBytes(innerPacketList)
                val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                    it.update(contentBytes)
                    it.digest()
                }
                assertEquals(0x76.toByte(), contentHashBytes[0])
                assertEquals(0xAC.toByte(), contentHashBytes[1])
                assertEquals(
                    "76ACF5ECAD6037C32F9D0085EDD468C4FBA48296395C05730F617045745B5D75",
                    contentHashBytes.toHex()
                )
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
                assertEquals(PublicKeyAlgorithm.ECDSA, packet0.publicKeyAlgorithm)
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
                assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
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
                val contentBytes = packetSignature.getContentBytes(innerPacketList)
                val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                    it.update(contentBytes)
                    it.digest()
                }
                assertEquals(0x27.toByte(), contentHashBytes[0])
                assertEquals(0x44.toByte(), contentHashBytes[1])
                assertEquals(
                    "27442302DFCEE4A7D9EBD80B86BB9DBAEEA7B4BA88C76BA8378E0F304495371E",
                    contentHashBytes.toHex()
                )
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
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
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
            val contentBytes = packetSignature.getContentBytes(contentData)
            val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                it.update(contentBytes)
                it.digest()
            }
            assertEquals(0x38.toByte(), contentHashBytes[0])
            assertEquals(0xE6.toByte(), contentHashBytes[1])
            assertEquals("38E618CF5D2FC787A095D71576CB7EE893879652AC17305347AE9F2A3CB22853", contentHashBytes.toHex())
        }

    }

    @Test
    fun decodeRsaSignatureTest() {
        val data =
            File(
                file.absolutePath,
                "hello_txt_signed_by_7B27AACBE3CCE445DABC4009A6ADD410C459A09B.gpg"
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
                assertEquals("A6ADD410C459A09B", packet0.keyId.toHex())
                assertEquals(HashAlgorithm.SHA2_256, packet0.hashAlgorithm)
                assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packet0.publicKeyAlgorithm)
                assertEquals(SignatureType.BinaryDocument, packet0.signatureType)
                assertEquals(0x01, packet0.flag)
            }

            val packet1 = innerPacketList[1]
            assertTrue(packet1 is PacketLiteralData)
            if (packet1 is PacketLiteralData) {
                assertEquals(1677767188, packet1.date)
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
                assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packetSignature.publicKeyAlgorithm)
                assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

                val hashedSubpackets = packetSignature.hashedSubpacketList
                assertEquals(2, hashedSubpackets.size)

                val issuerFingerprintSubpacket = hashedSubpackets[0]
                assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
                if (issuerFingerprintSubpacket is IssuerFingerprint) {
                    assertEquals(4, issuerFingerprintSubpacket.version)
                    assertEquals(
                        "7B27AACBE3CCE445DABC4009A6ADD410C459A09B",
                        issuerFingerprintSubpacket.fingerprint.toHex()
                    )
                }
                val signatureCreationTimeSubpacket = hashedSubpackets[1]
                assertEquals(
                    SubpacketType.SignatureCreationTime,
                    signatureCreationTimeSubpacket.getType()
                )
                if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                    assertEquals(1677767188, signatureCreationTimeSubpacket.value)
                }

                val subpackets = packetSignature.subpacketList
                assertEquals(1, subpackets.size)

                val issuerSubpacket = subpackets[0]
                assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
                if (issuerSubpacket is Issuer) {
                    assertEquals(
                        "A6ADD410C459A09B",
                        issuerSubpacket.keyId.toHex()
                    )
                }

                val hash2bytes = packetSignature.hash2bytes
                assertEquals(2, hash2bytes.size)
                assertEquals(
                    "EA89",
                    hash2bytes.toHex()
                )

                val signature = packetSignature.signature
                assertNotNull(signature)
                signature ?: return

                assertTrue(signature is SignatureRsa)
                if (signature is SignatureRsa) {
                    assertEquals(
                        "131F1D5562F6CF019FB48A1E43DCC25CC1225D27B9E36CEA3B1DF776D2ADEFBB977C50AC5585273355BCE825A96028BD3043696FC61B4ACAF6E0ABC8C29CDD07B96DAF5E3797A5ADE1A0D37206A9E36CFA6D7375921B57648B85BB60D04DE7DCD985EC81383A0F7113F077910BD63BEBEFC2C24601C4857A349B561E550A2836B9B5F1A90CCA68860B5CD6AFF307F1F20440E7551B14320A1DBB7A1FAD3920B4EFF0B1C3D08A05093618AFAD1D35D13F16FF7870B42831C7DBD1FAC2D3CCF5F2C103E8F1851B4827E4756CE5E5B9DFA7E01C6BF27BDF25942210B7B8FE0FD8A5756165FE14EFC86B0661B30CE984F95CC053AB39CAD38A1D286C92F5082A1E566AAE9EC025649F65BF54994FB06939647264E433612EEDE715DA29D89A0916583A57440F48CB966F867EE78CCAB09E141152E3460869C87F13D38AF0D005082709B901880D2E898C37A807C7396D4C0D48B2C6CA63F1885399100418B55924872E61758EC882F64537EB226DFC16DEC1CAE1825D1859624801B1CCCAAB535C05",
                        signature.value?.toHex(),
                    )
                }

                // Verify signature
                val contentBytes = packetSignature.getContentBytes(innerPacketList)
                val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                    it.update(contentBytes)
                    it.digest()
                }
                assertEquals(0xEA.toByte(), contentHashBytes[0])
                assertEquals(0x89.toByte(), contentHashBytes[1])
                assertEquals(
                    "EA89C3E7A6EC2E882A124FC7AF5953632EA3BF3325977BA4C7A4E8C973ABC5E8",
                    contentHashBytes.toHex()
                )
            }
        }
    }
}
