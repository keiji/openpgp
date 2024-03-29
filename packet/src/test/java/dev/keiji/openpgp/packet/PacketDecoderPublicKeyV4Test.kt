package dev.keiji.openpgp.packet

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.publickey.PacketPublicSubkeyV4
import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import dev.keiji.openpgp.packet.publickey.PublicKeyEddsa
import dev.keiji.openpgp.packet.publickey.PublicKeyRsa
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.SignatureEddsa
import dev.keiji.openpgp.packet.signature.SignatureRsa
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.packet.signature.subpacket.Features
import dev.keiji.openpgp.packet.signature.subpacket.Issuer
import dev.keiji.openpgp.packet.signature.subpacket.IssuerFingerprint
import dev.keiji.openpgp.packet.signature.subpacket.KeyExpirationTime
import dev.keiji.openpgp.packet.signature.subpacket.KeyFlags
import dev.keiji.openpgp.packet.signature.subpacket.KeyServerPreferences
import dev.keiji.openpgp.packet.signature.subpacket.PreferredCompressionAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.PreferredHashAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.PreferredSymmetricAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.SignatureCreationTime
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import java.io.File
import org.junit.jupiter.api.Test

class PacketDecoderPublicKeyV4Test {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeCallbackTest() {
        val publicKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
        )

        val pgpData = PgpData.load(publicKeyFile)
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        PacketDecoder.decode(data, object : PacketDecoder.Callback {
            override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                when (header.tagValue) {
                    0x02 -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("144", header.length.toString())
                    }

                    0x06 -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("82", header.length.toString())
                    }

                    0x0d -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("33", header.length.toString())
                    }
                }
            }
        })
    }

    @Test
    fun decodePublicKeyEcdsaTest() {
        val publicKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
        )

        val pgpData = PgpData.load(publicKeyFile)
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        val packetList = PacketDecoder.decode(data)
        assertEquals(3, packetList.size)

        val packetPublicKey = packetList[0]
        assertEquals(Tag.PublicKey, packetPublicKey.tag)
        if (packetPublicKey is PacketPublicKey) {
            assertEquals(4, packetPublicKey.version)
            assertEquals(1669682020, packetPublicKey.createdDateTimeEpoch)
        }
        if (packetPublicKey is PacketPublicKeyV4) {
            assertEquals(PublicKeyAlgorithm.ECDSA, packetPublicKey.algorithm)

            val publicKey = packetPublicKey.publicKey
            assertTrue(publicKey is PublicKeyEcdsa)
            if (publicKey is PublicKeyEcdsa) {
                assertEquals(
                    EllipticCurveParameter.Secp256r1,
                    publicKey.ellipticCurveParameter
                )
                assertEquals(
                    "04" +
                            "854E700A5524ADE7A11BF615C2F117AAA08EBFF455C4349B8B132878E2AAC527" +
                            "77573ED9594ECB013D5212C475DAFEF67D417BED81403F140A17506D7406244C",
                    publicKey.ecPoint?.toHex("")
                )
                assertEquals(
                    "854E700A5524ADE7A11BF615C2F117AAA08EBFF455C4349B8B132878E2AAC527",
                    publicKey.ecPointX?.toHex("")
                )
                assertEquals(
                    "77573ED9594ECB013D5212C475DAFEF67D417BED81403F140A17506D7406244C",
                    publicKey.ecPointY?.toHex("")
                )
            }
        }

        val packetUserId = packetList[1]
        assertEquals(Tag.UserId, packetUserId.tag)
        if (packetUserId is PacketUserId) {
            assertEquals("Keiji TEST (test) <TEST@test.com>", packetUserId.userId)
        }

        val packetSignature = packetList[2]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.PositiveCertificationOfUserId,
                packetSignature.signatureType
            )
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

            val hashedSubpackets = packetSignature.hashedSubpacketList
            assertEquals(8, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                    issuerFingerprintSubpacket.fingerprint.toHex("")
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1669682020, signatureCreationTimeSubpacket.value)
            }

            val keyFlagsSubpacket = hashedSubpackets[2]
            assertEquals(SubpacketType.KeyFlags, keyFlagsSubpacket.getType())
            if (keyFlagsSubpacket is KeyFlags) {
                assertArrayEquals(byteArrayOf(0x03), keyFlagsSubpacket.flags)
            }

            val preferredSymmetricAlgorithmsSubpacket = hashedSubpackets[3]
            assertEquals(
                SubpacketType.PreferredSymmetricAlgorithms,
                preferredSymmetricAlgorithmsSubpacket.getType()
            )
            if (preferredSymmetricAlgorithmsSubpacket is PreferredSymmetricAlgorithms) {
                assertEquals(4, preferredSymmetricAlgorithmsSubpacket.ids.size)
                assertEquals(
                    SymmetricKeyAlgorithm.AES256,
                    preferredSymmetricAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES192,
                    preferredSymmetricAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES128,
                    preferredSymmetricAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.TripleDES,
                    preferredSymmetricAlgorithmsSubpacket.ids[3]
                )
            }

            val preferredHashAlgorithmsSubpacket = hashedSubpackets[4]
            assertEquals(
                SubpacketType.PreferredHashAlgorithms,
                preferredHashAlgorithmsSubpacket.getType()
            )
            if (preferredHashAlgorithmsSubpacket is PreferredHashAlgorithms) {
                assertEquals(5, preferredHashAlgorithmsSubpacket.ids.size)
                assertEquals(
                    HashAlgorithm.SHA2_512,
                    preferredHashAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    HashAlgorithm.SHA2_384,
                    preferredHashAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    HashAlgorithm.SHA2_256,
                    preferredHashAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    HashAlgorithm.SHA2_224,
                    preferredHashAlgorithmsSubpacket.ids[3]
                )
                assertEquals(
                    HashAlgorithm.SHA1,
                    preferredHashAlgorithmsSubpacket.ids[4]
                )
            }

            val preferredCompressionAlgorithmsSubpacket = hashedSubpackets[5]
            assertEquals(
                SubpacketType.PreferredCompressionAlgorithms,
                preferredCompressionAlgorithmsSubpacket.getType()
            )
            if (preferredCompressionAlgorithmsSubpacket is PreferredCompressionAlgorithms) {
                assertEquals(3, preferredCompressionAlgorithmsSubpacket.ids.size)
                assertEquals(
                    CompressionAlgorithm.ZLIB,
                    preferredCompressionAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    CompressionAlgorithm.BZip2,
                    preferredCompressionAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    CompressionAlgorithm.ZIP,
                    preferredCompressionAlgorithmsSubpacket.ids[2]
                )
            }

            val featuresSubpacket = hashedSubpackets[6]
            assertEquals(
                SubpacketType.Features,
                featuresSubpacket.getType()
            )
            if (featuresSubpacket is Features) {
                assertArrayEquals(
                    byteArrayOf(0x01),
                    featuresSubpacket.flags
                )
            }

            val keyServerPreferencesSubpacket = hashedSubpackets[7]
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            if (keyServerPreferencesSubpacket is KeyServerPreferences) {
                assertArrayEquals(
                    byteArrayOf(0x80.toByte()),
                    keyServerPreferencesSubpacket.flags
                )
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "3E58DE6CC926B4AD",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "F61D",
                hash2bytes.toHex("")
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "14BCC222F597DF807DAB367D8C614377248574491397C9AB5B3EC63D0B1372A9",
                    signature.r?.toHex(""),
                )
                assertEquals(
                    "1EF8082B5EC9CFD88AB90A0C1179D4A5706A906DB279D02FB7DCCBE8430DC9B2",
                    signature.s?.toHex(""),
                )
            }
        }
    }

    @Test
    fun decodePublicKeyRsa3072Test() {
        val publicKeyFile = File(
            file.absolutePath,
            "BEE2304E4B50BA1E4627E845A7B65607A26BC985_rsa3072_publickey.gpg"
        )

        val pgpData = PgpData.load(publicKeyFile)
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        val packetList = PacketDecoder.decode(data)
        assertEquals(5, packetList.size)

        val packetPublicKey = packetList[0]
        assertEquals(Tag.PublicKey, packetPublicKey.tag)
        if (packetPublicKey is PacketPublicKey) {
            assertEquals(4, packetPublicKey.version)
            assertEquals(1669533494, packetPublicKey.createdDateTimeEpoch)
        }
        if (packetPublicKey is PacketPublicKeyV4) {
            assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packetPublicKey.algorithm)

            val publickey = packetPublicKey.publicKey
            assertTrue(publickey is PublicKeyRsa)
            if (publickey is PublicKeyRsa) {
                assertEquals(
                    "BBC55BA0253DFB1D7E90D475C4EDA97A1813ABE9332FE737C888FE8DF1D7D209A92B6A849FFB0E94634C57E0DEB93214D843303F5ACFF31A747C0D181795A7DC10694BECA04C7673036CB7BBC44F9608AEE06655EDC8624A0CE2A8B783165B535883EA4286FAEAC31911D74B970B7BD609ABD7B1EB1285B83EF90995EDCB709F0847EBBE5DFCFBAFBF851AF97B87E044466F9824700219BE737B8B62A2D4C3A64121C822BAC466EC810F84B572A2E6A841E3C4E486AB7C5142850AD7B97A1BE034EDB99A1F7C060203A8F25A3E34A10635B119F7685F941C45E6DAA9C88E8C828BCDF65A9FAECCB83D38BB3836EE4F1B9CF2DE643BB5C9E5DDC345E0FD56BCF69EB0B5A12F75106715C307BC81B15A98A7CE453ED6853890477B78E9E18FE69B953FF28950CD1110789F3BD5AEA29E23F10B7CFC98CB1900D04395090BE37470A91FE71020A2D45F9428B3A11E1A05DB14EFE5BD7B5F51723F0D144F948B83D1E0C3DBF5BD813DBC5E6E0DCE12F829D416B6D651162C7E0DC3B9C174DD421D27",
                    publickey.n?.toHex("")
                )
                assertEquals(
                    "010001",
                    publickey.e?.toHex("")
                )
            }
        }

        val packetUserId = packetList[1]
        assertEquals(Tag.UserId, packetUserId.tag)
        if (packetUserId is PacketUserId) {
            assertEquals("TEST ARIYAMA <keiji@test.com>", packetUserId.userId)
        }

        val packetSignature = packetList[2]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.PositiveCertificationOfUserId,
                packetSignature.signatureType
            )
            assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packetSignature.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

            val hashedSubpackets = packetSignature.hashedSubpacketList
            assertEquals(9, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "BEE2304E4B50BA1E4627E845A7B65607A26BC985",
                    issuerFingerprintSubpacket.fingerprint.toHex("")
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1669533494, signatureCreationTimeSubpacket.value)
            }

            val keyFlagsSubpacket = hashedSubpackets[2]
            assertEquals(SubpacketType.KeyFlags, keyFlagsSubpacket.getType())
            if (keyFlagsSubpacket is KeyFlags) {
                assertArrayEquals(byteArrayOf(0x03), keyFlagsSubpacket.flags)
            }

            val keyExpirationTimeSubpacket = hashedSubpackets[3]
            assertEquals(
                SubpacketType.KeyExpirationTime,
                keyExpirationTimeSubpacket.getType()
            )
            if (keyExpirationTimeSubpacket is KeyExpirationTime) {
                assertEquals(
                    63072000,
                    keyExpirationTimeSubpacket.value
                )
            }

            val preferredSymmetricAlgorithmsSubpacket = hashedSubpackets[4]
            assertEquals(
                SubpacketType.PreferredSymmetricAlgorithms,
                preferredSymmetricAlgorithmsSubpacket.getType()
            )
            if (preferredSymmetricAlgorithmsSubpacket is PreferredSymmetricAlgorithms) {
                assertEquals(4, preferredSymmetricAlgorithmsSubpacket.ids.size)
                assertEquals(
                    SymmetricKeyAlgorithm.AES256,
                    preferredSymmetricAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES192,
                    preferredSymmetricAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES128,
                    preferredSymmetricAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.TripleDES,
                    preferredSymmetricAlgorithmsSubpacket.ids[3]
                )
            }

            val preferredHashAlgorithmsSubpacket = hashedSubpackets[5]
            assertEquals(
                SubpacketType.PreferredHashAlgorithms,
                preferredHashAlgorithmsSubpacket.getType()
            )
            if (preferredHashAlgorithmsSubpacket is PreferredHashAlgorithms) {
                assertEquals(5, preferredHashAlgorithmsSubpacket.ids.size)
                assertEquals(
                    HashAlgorithm.SHA2_512,
                    preferredHashAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    HashAlgorithm.SHA2_384,
                    preferredHashAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    HashAlgorithm.SHA2_256,
                    preferredHashAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    HashAlgorithm.SHA2_224,
                    preferredHashAlgorithmsSubpacket.ids[3]
                )
                assertEquals(
                    HashAlgorithm.SHA1,
                    preferredHashAlgorithmsSubpacket.ids[4]
                )
            }

            val preferredCompressionAlgorithmsSubpacket = hashedSubpackets[6]
            assertEquals(
                SubpacketType.PreferredCompressionAlgorithms,
                preferredCompressionAlgorithmsSubpacket.getType()
            )
            if (preferredCompressionAlgorithmsSubpacket is PreferredCompressionAlgorithms) {
                assertEquals(3, preferredCompressionAlgorithmsSubpacket.ids.size)
                assertEquals(
                    CompressionAlgorithm.ZLIB,
                    preferredCompressionAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    CompressionAlgorithm.BZip2,
                    preferredCompressionAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    CompressionAlgorithm.ZIP,
                    preferredCompressionAlgorithmsSubpacket.ids[2]
                )
            }

            val featuresSubpacket = hashedSubpackets[7]
            assertEquals(
                SubpacketType.Features,
                featuresSubpacket.getType()
            )
            if (featuresSubpacket is Features) {
                assertArrayEquals(
                    byteArrayOf(0x01),
                    featuresSubpacket.flags
                )
            }

            val keyServerPreferencesSubpacket = hashedSubpackets[8]
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            if (keyServerPreferencesSubpacket is KeyServerPreferences) {
                assertArrayEquals(
                    byteArrayOf(0x80.toByte()),
                    keyServerPreferencesSubpacket.flags
                )
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "A7B65607A26BC985",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "474D",
                hash2bytes.toHex("")
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureRsa)
            if (signature is SignatureRsa) {
                assertEquals(
                    "0BE6816708B4156D25F8A90CF399271554A109919DF3A3E5A365EF323DDE7C164DDE42A351871902607ACD6A6682AC2B7241C5D8F664D8A877AD8152C4C937CEB524EA18FE12BD94A005630E6BF2DDAD3D81681E1476EAAE9FFE630040582E91848864401B3C587DB29E92242B6B1B87F7EFFCBC123BC99EFF64C54A5700C67DC03ECDD312558CB43F6F6009E4A77FA2343104353258D17ACD272C2917F698F115F6360253DC0305B9DDD45616DD109FC5360FD07C19F26EDA20015C49FA5EF66D7730E1359AA452B4134C88CAECC39692E2C85CCE78EE72412EE0B19B77187A6EFA09D7C9355BC3F2B3859BC19983152727A9F5B34E36DC51E3F0AD67FCCCB0CF783AD9830B783969B467D406604D819B847823245D2E74F4504ADFBEEDBFD6F57B87F2EA39428409A14B4CA6CE27126716CD641995A520909373ACA6D2A1E08F003DF316EDF25B9AACE8D9230D4B32EF50B99E495AC043972048262465555B5D17FFB8821E2C481718A896A654704E3298465330D9B5DBD53B9C0815F7A3AF",
                    signature.value?.toHex(""),
                )
            }
        }

        val packetPublicSubkey = packetList[3]
        assertTrue(packetPublicSubkey is PacketPublicSubkeyV4)
        if (packetPublicSubkey is PacketPublicSubkeyV4) {
            assertEquals(Tag.PublicSubkey, packetPublicSubkey.tag)
            assertEquals(4, packetPublicSubkey.version)
            assertEquals(
                PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN,
                packetPublicSubkey.algorithm
            )

            val publicSubkey = packetPublicSubkey.publicKey
            assertTrue(publicSubkey is PublicKeyRsa)
            if (publicSubkey is PublicKeyRsa) {
                assertEquals(
                    "CD94F3E77BE0072D2BF0764FB401D466F12B8EF4DB45BCF2DD3B026D34E53A4F1CAA2CD81CCE8105982A09FC94B4AF9774E938E2D839806F39F121E79944E60B15BB24F227394598127ED14FB582599F910AE7B6FF87142511197D4F8B7784E5F1737E46F11653CB92AA93EB4CEBEB8D9DEE07DA69CE7D30AC6971432B0126E3822BDBA32EA351FE7A15E438D5598590BED54D838F0F938642B038799DA64A8D1027946BE16C65AF91C268ADBB0D666329AFDC2197E33C0C100FF64AB495665323F421DBDA902D9F8E3666C562D43636338DDC1E54E2F4A1259A9D29CCDA3398B4EDB86FA3B9BA23FB675988C2EBB9DF0E592AB4F05E3A40583E9A1721AB09BEA986EC9B23C8B6FD9E02EBFDB23C81786687C189980AE8C46D1014A9B8F5AD9F97E3F3CEE9590D5882BB1EFD12CC094FE7A35336A5B7800A97F6F944D65538218A6D5A78A06C9CBCB574381A1FAF940FF632E27D57787DD71AFA00354C0DE68D495819C7976E685D0C558FFA52D0E582B932BA334D63052470DB8A8FE266D743",
                    publicSubkey.n?.toHex("")
                )
                assertEquals(
                    "010001",
                    publicSubkey.e?.toHex("")
                )
            }
        }

        val packetSignature2 = packetList[4]
        assertTrue(packetSignature2 is PacketSignatureV4)
        if (packetSignature2 is PacketSignatureV4) {
            assertEquals(
                SignatureType.SubKeyBinding,
                packetSignature2.signatureType
            )
            assertEquals(
                PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN,
                packetSignature2.publicKeyAlgorithm
            )
            assertEquals(HashAlgorithm.SHA2_256, packetSignature2.hashAlgorithm)

            val hashedSubpackets = packetSignature2.hashedSubpacketList
            assertEquals(4, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "BEE2304E4B50BA1E4627E845A7B65607A26BC985",
                    issuerFingerprintSubpacket.fingerprint.toHex("")
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1669533494, signatureCreationTimeSubpacket.value)
            }

            val keyFlagsSubpacket = hashedSubpackets[2]
            assertEquals(SubpacketType.KeyFlags, keyFlagsSubpacket.getType())
            if (keyFlagsSubpacket is KeyFlags) {
                assertArrayEquals(byteArrayOf(12), keyFlagsSubpacket.flags)
            }

            val keyExpirationTimeSubpacket = hashedSubpackets[3]
            assertEquals(SubpacketType.KeyExpirationTime, keyExpirationTimeSubpacket.getType())
            assertEquals(
                SubpacketType.KeyExpirationTime,
                keyExpirationTimeSubpacket.getType()
            )
            if (keyExpirationTimeSubpacket is KeyExpirationTime) {
                assertEquals(63072000, keyExpirationTimeSubpacket.value)
            }

            val subpackets = packetSignature2.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "A7B65607A26BC985",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature2.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "7BAC",
                hash2bytes.toHex("")
            )

            val signature = packetSignature2.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureRsa)
            if (signature is SignatureRsa) {
                assertEquals(
                    "32EF13A87BECC538122CEA1D498A8C4214FAD5E796AA76F1AF6651E03C1AA232ECE21998C0E8D94D18DB39311B94CCBAD2B1C94921551D1645E79E1A4208C1078B1C5FFC0F16703266FE0F3103B77580B3F166E71092A33D1B0544EA094088FAD2A5AE194B728CC35865E0FC53CD185574B0418ABBED4F0964B5CBD22FD6CDDD8F4A646B15A695F88D1EA90D5F557306EC341796192A2627A29CFF575D02CB539A9D1308D0AFADE94F742524218A173DBA6D6823FFF7B435197DA0FC622A16785FE273FA53CAA86B9A9E3A62F7EBB0B9E89B6ADD08F0BA3B923470C2C07488CC2A73452078DEED079D105AD55609DE79A30993B4A9048F112A3925E081123B7F9FA748D76AF6A8E1E69C8D0E2E80E87941A86169892960F966C845E42EEC4F359885474E530375B251DD638F7806F0C9436383C351F8024C4992485B1DA31419054C5431AD83835A833A03DD2EE729E1B7BF4F54C92C92B1F4493722D1EA8F02C088A70048A610E20914CA51BF786B0FDBA0D52765067A3EF68D315FCE5BD6EE",
                    signature.value?.toHex(""),
                )
            }
        }
    }

    @Test
    fun decodePublicKeySignedTest() {
        val publicKeyFile = File(
            file.absolutePath,
            "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A_ecdsa_publickey_signedby_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )

        val pgpData = PgpData.load(publicKeyFile)
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        val packetList = PacketDecoder.decode(data)
        assertEquals(4, packetList.size)

        val packetPublicKey = packetList[0]
        assertEquals(Tag.PublicKey, packetPublicKey.tag)
        if (packetPublicKey is PacketPublicKey) {
            assertEquals(4, packetPublicKey.version)
            assertEquals(1669448543, packetPublicKey.createdDateTimeEpoch)
        }
        if (packetPublicKey is PacketPublicKeyV4) {
            assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetPublicKey.algorithm)

            val publicKey = packetPublicKey.publicKey
            assertTrue(publicKey is PublicKeyEddsa)
            if (publicKey is PublicKeyEddsa) {
                assertEquals(
                    EllipticCurveParameter.Ed25519,
                    publicKey.ellipticCurveParameter
                )
                assertEquals(
                    "40798EE8F951B43F308C4B5B29684678A0F2893E021532F070B5B5C94E1D01EE33",
                    publicKey.ecPoint?.toHex("")
                )
            }
        }

        val packetUserId = packetList[1]
        assertEquals(Tag.UserId, packetUserId.tag)
        if (packetUserId is PacketUserId) {
            assertEquals("TEST ARIYAMA (test) <keiji@test.com>", packetUserId.userId)
        }

        val packetSignature = packetList[2]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.PositiveCertificationOfUserId,
                packetSignature.signatureType
            )
            assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetSignature.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

            val hashedSubpackets = packetSignature.hashedSubpacketList
            assertEquals(8, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A",
                    issuerFingerprintSubpacket.fingerprint.toHex("")
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1669448543, signatureCreationTimeSubpacket.value)
            }

            val keyFlagsSubpacket = hashedSubpackets[2]
            assertEquals(SubpacketType.KeyFlags, keyFlagsSubpacket.getType())
            if (keyFlagsSubpacket is KeyFlags) {
                assertArrayEquals(byteArrayOf(0x03), keyFlagsSubpacket.flags)
            }

            val preferredSymmetricAlgorithmsSubpacket = hashedSubpackets[3]
            assertEquals(
                SubpacketType.PreferredSymmetricAlgorithms,
                preferredSymmetricAlgorithmsSubpacket.getType()
            )
            if (preferredSymmetricAlgorithmsSubpacket is PreferredSymmetricAlgorithms) {
                assertEquals(4, preferredSymmetricAlgorithmsSubpacket.ids.size)
                assertEquals(
                    SymmetricKeyAlgorithm.AES256,
                    preferredSymmetricAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES192,
                    preferredSymmetricAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.AES128,
                    preferredSymmetricAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    SymmetricKeyAlgorithm.TripleDES,
                    preferredSymmetricAlgorithmsSubpacket.ids[3]
                )
            }

            val preferredHashAlgorithmsSubpacket = hashedSubpackets[4]
            assertEquals(
                SubpacketType.PreferredHashAlgorithms,
                preferredHashAlgorithmsSubpacket.getType()
            )
            if (preferredHashAlgorithmsSubpacket is PreferredHashAlgorithms) {
                assertEquals(5, preferredHashAlgorithmsSubpacket.ids.size)
                assertEquals(
                    HashAlgorithm.SHA2_512,
                    preferredHashAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    HashAlgorithm.SHA2_384,
                    preferredHashAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    HashAlgorithm.SHA2_256,
                    preferredHashAlgorithmsSubpacket.ids[2]
                )
                assertEquals(
                    HashAlgorithm.SHA2_224,
                    preferredHashAlgorithmsSubpacket.ids[3]
                )
                assertEquals(
                    HashAlgorithm.SHA1,
                    preferredHashAlgorithmsSubpacket.ids[4]
                )
            }

            val preferredCompressionAlgorithmsSubpacket = hashedSubpackets[5]
            assertEquals(
                SubpacketType.PreferredCompressionAlgorithms,
                preferredCompressionAlgorithmsSubpacket.getType()
            )
            if (preferredCompressionAlgorithmsSubpacket is PreferredCompressionAlgorithms) {
                assertEquals(3, preferredCompressionAlgorithmsSubpacket.ids.size)
                assertEquals(
                    CompressionAlgorithm.ZLIB,
                    preferredCompressionAlgorithmsSubpacket.ids[0]
                )
                assertEquals(
                    CompressionAlgorithm.BZip2,
                    preferredCompressionAlgorithmsSubpacket.ids[1]
                )
                assertEquals(
                    CompressionAlgorithm.ZIP,
                    preferredCompressionAlgorithmsSubpacket.ids[2]
                )
            }

            val featuresSubpacket = hashedSubpackets[6]
            assertEquals(
                SubpacketType.Features,
                featuresSubpacket.getType()
            )
            if (featuresSubpacket is Features) {
                assertArrayEquals(
                    byteArrayOf(0x01),
                    featuresSubpacket.flags
                )
            }

            val keyServerPreferencesSubpacket = hashedSubpackets[7]
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            assertEquals(
                SubpacketType.KeyServerPreferences,
                keyServerPreferencesSubpacket.getType()
            )
            if (keyServerPreferencesSubpacket is KeyServerPreferences) {
                assertArrayEquals(
                    byteArrayOf(0x80.toByte()),
                    keyServerPreferencesSubpacket.flags
                )
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "A71E2CA57AC1F09A",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "FFD2",
                hash2bytes.toHex("")
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEddsa)
            if (signature is SignatureEddsa) {
                assertEquals(
                    "32601BC71ED47D87FCB7535BDBAFF841051CB87FC2E4D01A6AB0900E12EAF58B",
                    signature.r?.toHex(""),
                )
                assertEquals(
                    "1E5B16DAF235D4086612B8EEDBA296585EF1115F947F0D2BE803CA8AB2BD990F",
                    signature.s?.toHex(""),
                )
            }
        }

        val packetSignature2 = packetList[3]
        assertEquals(Tag.Signature, packetSignature2.tag)
        assertTrue(packetSignature2 is PacketSignatureV4)
        if (packetSignature2 is PacketSignatureV4) {
            assertEquals(
                SignatureType.GenericCertificationOfUserId,
                packetSignature2.signatureType
            )
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature2.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature2.hashAlgorithm)

            val hashedSubpackets = packetSignature2.hashedSubpacketList
            assertEquals(2, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                    issuerFingerprintSubpacket.fingerprint.toHex("")
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1671637004, signatureCreationTimeSubpacket.value)
            }

            val subpackets = packetSignature2.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "3E58DE6CC926B4AD",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature2.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "5AB8",
                hash2bytes.toHex("")
            )

            val signature = packetSignature2.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "B701D72D4D09C2D80CA33B04FAECCB6DF36277B6B4C8752A8DDEDF75991DCABD",
                    signature.r?.toHex(""),
                )
                assertEquals(
                    "EEE8680C49BC4EE603EABA6A0D24B27FBAD203F9485422C481B72A58ACB17637",
                    signature.s?.toHex(""),
                )
            }
        }
    }
}
