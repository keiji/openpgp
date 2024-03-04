package dev.keiji.openpgp.packet

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.KdfUtils
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import dev.keiji.openpgp.packet.publickey.PublicKeyRsa
import dev.keiji.openpgp.packet.secretkey.PacketSecretKeyV4
import dev.keiji.openpgp.packet.secretkey.PacketSecretSubkeyV4
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyGNUDummyS2K
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeySaltedIterated
import dev.keiji.openpgp.packet.signature.SignatureRsa
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.String2KeyType
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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.File

class PacketDecoderSecretKeyV4Test {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeCallbackTest() {
        val secretKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_ecdsa_secretkey.gpg"
        )

        val secretKeyPgpData = PgpData.loadAsciiArmored(secretKeyFile)
        val secretKeyData = secretKeyPgpData.blockList[0].data
        assertNotNull(secretKeyData)
        secretKeyData ?: return

        PacketDecoder.decode(secretKeyData, object : PacketDecoder.Callback {
            override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                when (header.tagValue) {
                    0x05 -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("165", header.length.toString())
                    }
                    0x0D -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("33", header.length.toString())
                    }
                    0x02 -> {
                        assertTrue(header.isLegacyFormat)
                        assertEquals("144", header.length.toString())
                    }
                    else -> fail("")
                }
            }
        })
    }

    @Test
    fun decodeSecretKeyEcdsaTest() {
        val secretKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_ecdsa_secretkey.gpg"
        )

        val secretKeyPgpData = PgpData.loadAsciiArmored(secretKeyFile)
        val secretKeyData = secretKeyPgpData.blockList[0].data
        assertNotNull(secretKeyData)
        secretKeyData ?: return

        val packetList = PacketDecoder.decode(secretKeyData)
        assertEquals(3, packetList.size)

        val packetSecretKey = packetList[0]
        assertEquals(Tag.SecretKey, packetSecretKey.tag)
        if (packetSecretKey is PacketSecretKeyV4) {
            assertEquals(4, packetSecretKey.version)
            assertEquals(1669682020, packetSecretKey.createdDateTimeEpoch)
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSecretKey.algorithm)

            val publicKey = packetSecretKey.publicKey
            assertTrue(publicKey is PublicKeyEcdsa)
            if (publicKey is PublicKeyEcdsa) {
                assertEquals(
                    EllipticCurveParameter.Secp256r1,
                    publicKey.ellipticCurveParameter
                )
                assertEquals(
                    "04854E700A5524ADE7A11BF615C2F117AAA08EBFF455C4349B8B132878E2AAC52777573ED9594ECB013D5212C475DAFEF67D417BED81403F140A17506D7406244C",
                    publicKey.ecPoint?.toHex("")
                )
            }

            assertEquals(SecretKeyEncryptionType.SHA1, packetSecretKey.string2keyUsage)

            assertEquals(
                SymmetricKeyAlgorithm.AES128,
                packetSecretKey.symmetricKeyEncryptionAlgorithm
            )
            assertNull(packetSecretKey.aeadAlgorithm)

            val string2Key = packetSecretKey.string2Key
            assertEquals(String2KeyType.SALTED_ITERATED, string2Key?.type)
            if (string2Key is String2KeySaltedIterated) {
                assertEquals(HashAlgorithm.SHA1, string2Key.hashAlgorithm)
                assertEquals(
                    "5FCB5E72807D3243",
                    string2Key.salt.toHex("")
                )
                assertEquals(
                    54525952,
                    KdfUtils.calculateIterationCount(string2Key.iterationCount)
                )
                assertEquals(HashAlgorithm.SHA1, string2Key.hashAlgorithm)
                assertEquals(
                    "FD0835EA271C41C3",
                    packetSecretKey.initializationVector?.toHex("")
                )
            }

            val encryptedKey = packetSecretKey.data
            assertEquals(62, encryptedKey?.size)
            assertEquals(
                "5F4D890B4E6284531B4CFE45CB59A8F1FD197EBE6CC72BC432E4728460010BFF7EB47841231909F561829DE57E8C53CCD3C8CFCB418325B0214B353FAC48",
                encryptedKey?.toHex("")
            )
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
    fun decodeSecretKeyRsa3072Test() {
        val secretKeyFile = File(
            file.absolutePath,
            "BEE2304E4B50BA1E4627E845A7B65607A26BC985_rsa3072_secretkey.gpg"
        )

        val secretKeyPgpData = PgpData.loadAsciiArmored(secretKeyFile)
        val secretKeyData = secretKeyPgpData.blockList[0].data
        assertNotNull(secretKeyData)
        secretKeyData ?: return

        val packetList = PacketDecoder.decode(secretKeyData)
        assertEquals(5, packetList.size)

        val packetSecretKey = packetList[0]
        assertEquals(Tag.SecretKey, packetSecretKey.tag)
        if (packetSecretKey is PacketSecretKeyV4) {
            assertEquals(4, packetSecretKey.version)
            assertEquals(1669533494, packetSecretKey.createdDateTimeEpoch)
            assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packetSecretKey.algorithm)

            val publicKey = packetSecretKey.publicKey
            assertTrue(publicKey is PublicKeyRsa)
            if (publicKey is PublicKeyRsa) {
                assertEquals(
                    "BBC55BA0253DFB1D7E90D475C4EDA97A1813ABE9332FE737C888FE8DF1D7D209A92B6A849FFB0E94634C57E0DEB93214D843303F5ACFF31A747C0D181795A7DC10694BECA04C7673036CB7BBC44F9608AEE06655EDC8624A0CE2A8B783165B535883EA4286FAEAC31911D74B970B7BD609ABD7B1EB1285B83EF90995EDCB709F0847EBBE5DFCFBAFBF851AF97B87E044466F9824700219BE737B8B62A2D4C3A64121C822BAC466EC810F84B572A2E6A841E3C4E486AB7C5142850AD7B97A1BE034EDB99A1F7C060203A8F25A3E34A10635B119F7685F941C45E6DAA9C88E8C828BCDF65A9FAECCB83D38BB3836EE4F1B9CF2DE643BB5C9E5DDC345E0FD56BCF69EB0B5A12F75106715C307BC81B15A98A7CE453ED6853890477B78E9E18FE69B953FF28950CD1110789F3BD5AEA29E23F10B7CFC98CB1900D04395090BE37470A91FE71020A2D45F9428B3A11E1A05DB14EFE5BD7B5F51723F0D144F948B83D1E0C3DBF5BD813DBC5E6E0DCE12F829D416B6D651162C7E0DC3B9C174DD421D27",
                    publicKey.n?.toHex("")
                )
                assertEquals(
                    "010001",
                    publicKey.e?.toHex("")
                )
            }

            assertEquals(SecretKeyEncryptionType.CheckSum, packetSecretKey.string2keyUsage)

            assertEquals(
                SymmetricKeyAlgorithm.PlaintextOrUnencryptedData,
                packetSecretKey.symmetricKeyEncryptionAlgorithm
            )
            assertNull(packetSecretKey.aeadAlgorithm)

            val string2Key = packetSecretKey.string2Key
            assertEquals(String2KeyType.GNU_DUMMY_S2K, string2Key?.type)
            if (string2Key is String2KeyGNUDummyS2K) {
                assertEquals(
                    "00474E550210D276",
                    packetSecretKey.initializationVector?.toHex("")
                )
            }

            val encryptedKey = packetSecretKey.data
            assertEquals(14, encryptedKey?.size)
            assertEquals(
                "000124010304FFFF889A6D190000",
                encryptedKey?.toHex("")
            )
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

        val packetSecretSubkey = packetList[3]
        assertTrue(packetSecretSubkey is PacketSecretSubkeyV4)
        if (packetSecretSubkey is PacketSecretSubkeyV4) {
            assertEquals(Tag.SecretSubkey, packetSecretSubkey.tag)
            assertEquals(4, packetSecretSubkey.version)
            assertEquals(
                PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN,
                packetSecretSubkey.algorithm
            )

            val packetPublicSubkey = packetSecretSubkey.publicKey
            assertTrue(packetPublicSubkey is PublicKeyRsa)
            if (packetPublicSubkey is PublicKeyRsa) {
                assertEquals(
                    "CD94F3E77BE0072D2BF0764FB401D466F12B8EF4DB45BCF2DD3B026D34E53A4F1CAA2CD81CCE8105982A09FC94B4AF9774E938E2D839806F39F121E79944E60B15BB24F227394598127ED14FB582599F910AE7B6FF87142511197D4F8B7784E5F1737E46F11653CB92AA93EB4CEBEB8D9DEE07DA69CE7D30AC6971432B0126E3822BDBA32EA351FE7A15E438D5598590BED54D838F0F938642B038799DA64A8D1027946BE16C65AF91C268ADBB0D666329AFDC2197E33C0C100FF64AB495665323F421DBDA902D9F8E3666C562D43636338DDC1E54E2F4A1259A9D29CCDA3398B4EDB86FA3B9BA23FB675988C2EBB9DF0E592AB4F05E3A40583E9A1721AB09BEA986EC9B23C8B6FD9E02EBFDB23C81786687C189980AE8C46D1014A9B8F5AD9F97E3F3CEE9590D5882BB1EFD12CC094FE7A35336A5B7800A97F6F944D65538218A6D5A78A06C9CBCB574381A1FAF940FF632E27D57787DD71AFA00354C0DE68D495819C7976E685D0C558FFA52D0E582B932BA334D63052470DB8A8FE266D743",
                    packetPublicSubkey.n?.toHex("")
                )
                assertEquals(
                    "010001",
                    packetPublicSubkey.e?.toHex("")
                )
            }

            assertEquals(SecretKeyEncryptionType.SHA1, packetSecretSubkey.string2keyUsage)

            assertEquals(
                SymmetricKeyAlgorithm.AES128,
                packetSecretSubkey.symmetricKeyEncryptionAlgorithm
            )
            assertNull(packetSecretSubkey.aeadAlgorithm)

            val string2Key = packetSecretSubkey.string2Key
            assertEquals(String2KeyType.SALTED_ITERATED, string2Key?.type)
            if (string2Key is String2KeySaltedIterated) {
                assertEquals(
                    "5806C167CE09B0B5",
                    string2Key.salt.toHex("")
                )
                assertEquals(
                    54525952,
                    string2Key.iterationCount
                )
//                assertEquals(
//                    "D01266B74509785141ABD63936A4465E",
//                    string2Key.initializationVector?.toHex("")
//                )
            }

            val encryptedKey = packetSecretSubkey.data
            assertEquals(996, encryptedKey?.size)
            assertEquals(
                "41ABD63936A4465EDB14C3DC1A4F4368551EFEA7CB27414AC454BCBB4DC56097D686D64CE7943BAEE68ABF14E783D94CB8068A7C5664B54B411BD318009E191911EF5F16931119E4FB2CDBB9E3E74E7C51BB015D9F2E2C3947064EE62C801F9398292A9A8D920C6FB3E4DB0BCACC1D8A2817B657A807521BF4EEED2D6AE8350CC4C716FC09BE5EE9617F06FC2504001A55681A7C5DB97F1401C4EE2C14723EC8F56D378FF556F6B5B5832D468435031058F2EA4B1DA1C674BCDB2282461853096CA953EDF4A49E24DB5644B0C161FB39BA5101DD10AFC56D4707322AE066B86739CEB8B99404AD1CF20F80BE56EF98CD9378369DEA3635D427A1B13D23362ADE8667CAD484DCBC5F0A53F011CD67114C9F12381C1D131F31DAE040F4817626A86B7546EF654EBDF71354C6B70752B7143B9EF51F4427DDB9C135E094EADE13797513331EA1E2039A95C636C730051F2252979B97105A0E03F1C965A593E96E1C3878BF199E2178F76B6BDAF8788BE7B27A5FB0398E3A6C727F873BFF59B92E01FD00CC1C016B265E9D6DE28109B7B3AEC0444F2DCC6B3362B907ADC1F6DFE8EAE7408996E4A4562BDEA952AB9748EDA3BB82A6715342A420546D0FC5F191960E9F345B3ACE4E69087326233E6C887579FB9D8F034F7EC5CD2BDA63E46DDE1172E944C931E1875A6FCC6A06F886B4CFE2E4AFFB22DD1BEE909F08F8BEE0FD2396ABB49DDBA235C3A74D04E7582F6257515BCAEA3FDE041273A32486CC873C0D9A76580E10F849BA02E2FE86AD9516F924D4D9DD0CD8C771195A4AC8CABF33DE7AC84EA1BB1884BA5EA12EA1AD6AD0D27C0AFCA5D6CA64C167092ADCDC98FF716A901E55EE941A558331AFFA431464F5C7349D940AC9E32B282E3661B5EB560FCA8DCAFEE552F56FCBC519B3F949C76C55E4B54943F7F91D15C9F9428B7D760A2A8AFA19608496D5777A5D839A8F11A2DF7F74EC501B195685EA3D151EBE87EEC39C5CE27A99F92BF9FDD91946D5E6BFBBF58C1C7DF40AAE62B5E46E343FB1F3F1A39D083715589793941E002232D54CD2203EE0CCD9D457E87DEF4E1A2830CAC0B8E09FFC101C0F1CFB716F53928CF2BA57B14E148D77BF21FA4262965A3133658FA765A11C27EF29F459965990B602465050E8EFD3D94379603FCD87A56B8F428B516DDF16A9912C193883AAF001C2ED01957A32C954146751D51804E7468873B07745CB39ACAD7FBD49397455B5B099854A17BDF43B0BEC801511C1262B1F78A34DDE8AEA7931A74500DFAA9BD70A9BB81D55C864F7AB01A331D2586DE90B732B44EEE8C9415F939D2C41F557BA33D03BD19EF4A7D71EA7E22995E6E9B4132FCE8CB07AA5EA58176385ACE5255BE81BBFFD7ADDA237BE600718C61B848E6C5EE8DF5B43",
                encryptedKey?.toHex("")
            )
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
}
